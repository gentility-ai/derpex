defmodule Derpex.Writer do
  @moduledoc """
  The sole socket writer for one DERP connection.

  A wakeup drains the rings until they are empty. A ring locked by a producer
  ends the drain: the writer never re-wakes itself, it schedules one short retry
  because the producer may have coalesced its wake into the one being handled.
  """

  use GenServer

  alias Derpex.Cardinality
  alias Derpex.Frame.Body
  alias Derpex.Metrics
  alias Derpex.Outbox.Ring
  alias Derpex.WebSocket.Frame, as: WebSocketFrame

  @wake_message :derpex_outbox_ready
  @retry_message :derpex_outbox_retry
  @retry_interval_ms 5
  @websocket_chunk_size 16 * 1_024

  @type rings :: %{
          ordinary: Ring.t(),
          disco: Ring.t(),
          pong: Ring.t(),
          lifecycle: Ring.t()
        }

  @doc false
  def start_link(options) do
    GenServer.start_link(__MODULE__, options)
  end

  @doc "Attaches fixed rings before the connection is registered for routing."
  @spec attach(pid(), rings()) :: :ok
  def attach(writer, rings), do: GenServer.call(writer, {:attach, rings})

  @doc "Writes bounded handshake/HTTP control data in call order."
  @spec write_control(pid(), iodata(), timeout()) :: :ok | {:error, term()}
  def write_control(writer, data, timeout \\ 5_000),
    do: GenServer.call(writer, {:control, data}, timeout)

  @doc "Switches subsequent writes to RFC 6455 binary messages."
  @spec set_wire_mode(pid(), :native | :websocket) :: :ok
  def set_wire_mode(writer, mode) when mode in [:native, :websocket],
    do: GenServer.call(writer, {:wire_mode, mode})

  @doc "Writes a WebSocket pong without exposing socket ownership."
  @spec websocket_pong(pid(), binary()) :: :ok | {:error, term()}
  def websocket_pong(writer, payload), do: GenServer.call(writer, {:websocket_pong, payload})

  @doc "Estimates the distinct non-zero sources sent to this connection."
  @spec estimated_unique_senders(pid()) :: non_neg_integer()
  def estimated_unique_senders(writer), do: GenServer.call(writer, :estimated_unique_senders)

  @doc "The atom used for coalesced ring notification."
  @spec wake_message() :: atom()
  def wake_message, do: @wake_message

  @impl true
  def init(options) do
    owner = Keyword.fetch!(options, :owner)
    transport = Keyword.fetch!(options, :transport)
    socket = Keyword.fetch!(options, :socket)

    {:ok,
     %{
       owner: owner,
       owner_monitor: Process.monitor(owner),
       transport: transport,
       socket: socket,
       metrics: Keyword.get(options, :metrics),
       wire_mode: :native,
       rings: nil,
       retry_timer: nil,
       sender_cardinality: Cardinality.new()
     }}
  end

  @impl true
  def handle_call({:attach, rings}, _from, %{rings: nil} = state) do
    # A wakeup that arrived before the rings did was dropped, and the ring sends
    # no other one until an empty take clears its pending wake, so the first
    # drain happens here rather than waiting for a wakeup that never comes.
    case drain(%{state | rings: rings}) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason, state} -> {:stop, {:write_error, reason}, :ok, state}
    end
  end

  def handle_call({:control, data}, _from, state) do
    {:reply, send_data(state, data), state}
  end

  def handle_call({:wire_mode, mode}, _from, state) do
    {:reply, :ok, %{state | wire_mode: mode}}
  end

  def handle_call({:websocket_pong, payload}, _from, %{wire_mode: :websocket} = state) do
    result = state.transport.send(state.socket, WebSocketFrame.encode_pong(payload))
    {:reply, result, state}
  end

  def handle_call(:estimated_unique_senders, _from, state) do
    {:reply, Cardinality.estimate(state.sender_cardinality), state}
  end

  @impl true
  def handle_info(@wake_message, %{rings: rings} = state) when is_map(rings) do
    drain_or_stop(state)
  end

  def handle_info(@wake_message, state), do: {:noreply, state}

  def handle_info(@retry_message, %{rings: rings} = state) when is_map(rings) do
    drain_or_stop(%{state | retry_timer: nil})
  end

  def handle_info(@retry_message, state), do: {:noreply, %{state | retry_timer: nil}}

  def handle_info({:DOWN, monitor, :process, _owner, reason}, %{owner_monitor: monitor} = state) do
    {:stop, {:owner_down, reason}, state}
  end

  defp drain_or_stop(state) do
    case state |> cancel_retry() |> drain() do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:stop, {:write_error, reason}, state}
    end
  end

  defp drain(state) do
    case take_next(state.rings) do
      {:ok, message, queue_age_microseconds} ->
        with {:ok, frame} <- Body.encode_server(message),
             :ok <- send_data(state, frame) do
          record_queue_duration(state.metrics, message, queue_age_microseconds)
          record_send(state.metrics, message)
          maybe_note_send(state, message)
          drain(state)
        else
          {:error, reason} ->
            :ok = Metrics.add(state.metrics, :write_errors, 1)
            record_write_drop(state.metrics, message)
            {:error, reason, state}
        end

      :empty ->
        {:ok, state}

      :busy ->
        {:ok, schedule_retry(state)}

      :closed ->
        {:ok, state}
    end
  end

  # A producer holds the ring lock. It signals the wake flag under that lock, so
  # a wakeup is only guaranteed when the flag was clear; when it was already set
  # by the wakeup being handled right now, this timer is the one that comes back.
  defp schedule_retry(%{retry_timer: nil} = state) do
    %{state | retry_timer: Process.send_after(self(), @retry_message, @retry_interval_ms)}
  end

  defp schedule_retry(state), do: state

  # The drain that is starting supersedes an earlier retry, so the writer keeps
  # at most one outstanding retry and never accumulates timer messages.
  defp cancel_retry(%{retry_timer: nil} = state), do: state

  defp cancel_retry(%{retry_timer: timer} = state) do
    if Process.cancel_timer(timer) == false do
      receive do
        @retry_message -> :ok
      after
        0 -> :ok
      end
    end

    %{state | retry_timer: nil}
  end

  defp take_next(%{lifecycle: lifecycle} = rings) do
    case Ring.take_with_age(lifecycle) do
      :empty -> take_packet(rings)
      result -> result
    end
  end

  defp take_packet(%{ordinary: ordinary, disco: disco, pong: pong}) do
    case Ring.take_with_age(ordinary) do
      :empty ->
        case Ring.take_with_age(disco) do
          :empty -> Ring.take_with_age(pong)
          result -> result
        end

      result ->
        result
    end
  end

  defp maybe_note_send(_state, {:recv_packet, <<0::256>>, _packet}), do: :ok

  defp maybe_note_send(state, {:recv_packet, source, _packet}) do
    :ok = Cardinality.insert(state.sender_cardinality, source)
    Derpex.Router.note_send(source, state.owner, state.rings.lifecycle)
  end

  defp maybe_note_send(_state, _message), do: :ok

  defp record_send(metrics, {:recv_packet, _source, packet}) do
    :ok = Metrics.add(metrics, :packets_sent, 1)
    Metrics.add(metrics, :bytes_sent, byte_size(packet))
  end

  defp record_send(metrics, {:pong, _payload}), do: Metrics.add(metrics, :sent_pong, 1)

  defp record_send(metrics, {:peer_gone, _key, 0x00}),
    do: Metrics.add(metrics, :peer_gone_disconnected_frames, 1)

  defp record_send(metrics, {:peer_gone, _key, _reason}),
    do: Metrics.add(metrics, :peer_gone_not_here_frames, 1)

  defp record_send(_metrics, _message), do: :ok

  defp record_write_drop(metrics, {:recv_packet, _source, packet}) do
    kind = if Derpex.Disco.looks_like_wrapper?(packet), do: :disco, else: :other
    Metrics.add_drop(metrics, :write_error, kind, byte_size(packet))
  end

  defp record_write_drop(_metrics, _message), do: :ok

  defp record_queue_duration(metrics, {:recv_packet, _source, _packet}, microseconds),
    do: Metrics.observe_queue_duration(metrics, microseconds)

  defp record_queue_duration(_metrics, _message, _microseconds), do: :ok

  defp send_data(%{wire_mode: :native} = state, data),
    do: state.transport.send(state.socket, data)

  defp send_data(%{wire_mode: :websocket} = state, data),
    do: send_websocket_chunks(state, IO.iodata_to_binary(data))

  defp send_websocket_chunks(state, data) when byte_size(data) <= @websocket_chunk_size do
    state.transport.send(state.socket, WebSocketFrame.encode_binary(data))
  end

  defp send_websocket_chunks(state, data) do
    <<chunk::binary-size(@websocket_chunk_size), rest::binary>> = data

    case state.transport.send(state.socket, WebSocketFrame.encode_binary(chunk)) do
      :ok -> send_websocket_chunks(state, rest)
      {:error, _reason} = error -> error
    end
  end
end
