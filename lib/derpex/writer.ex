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
  alias Derpex.Outbox
  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Ring
  alias Derpex.Router
  alias Derpex.Router.ReversePaths
  alias Derpex.SocketOptions
  alias Derpex.WebSocket.Frame, as: WebSocketFrame

  @wake_message :derpex_outbox_ready
  @retry_message :derpex_outbox_retry
  # The shortest timer the BEAM will give: the retry is a safety net for a take
  # that met a producer's lock, and every millisecond it waits is a millisecond
  # of latency on packets that are already queued. At five it was visible as a
  # mode in the relay's latency histogram.
  @retry_interval_ms 1
  # Frames per wakeup. A writer that drains a full queue in one pass answers no
  # control write and no pong until it is done, so it gives the mailbox a turn.
  @max_drain_per_wake 64
  @websocket_chunk_size 16 * 1_024
  @packet_classes [:lifecycle, :ordinary, :disco, :pong]

  @type rings :: %{
          ordinary: Ring.t(),
          disco: Ring.t(),
          pong: Ring.t(),
          lifecycle: Ring.t() | LifecycleQueue.t()
        }

  @doc false
  def start_link(options) do
    GenServer.start_link(__MODULE__, options)
  end

  @doc """
  Attaches fixed rings before the connection is registered for routing.

  The attaching call drains whatever the rings already hold, so it reports a
  failed socket write rather than reporting success and stopping silently.
  """
  @spec attach(pid(), rings()) :: :ok | {:error, term()}
  def attach(writer, rings), do: GenServer.call(writer, {:attach, rings})

  @doc """
  Writes bounded handshake/HTTP control data in call order.

  The caller passes its own socket write timeout plus a margin: giving up
  sooner than the socket does would abandon a write that is still legitimately
  in flight, and a mesh peer is allowed thirty seconds.
  """
  @spec write_control(pid(), iodata(), timeout()) :: :ok | {:error, term()}
  def write_control(writer, data, timeout \\ SocketOptions.default_write_timeout_ms() + 1_000),
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

    # The owner links the writer and ends an ordinary connection with
    # {:shutdown, _} — a closed peer, a drain deadline, a lifecycle overflow.
    # An untrapped signal kills the writer where it stands, so terminate/2 never
    # runs and the reverse paths it recorded outlive the queue they name.
    Process.flag(:trap_exit, true)

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
       packet_cursor: 0,
       noted_sources: MapSet.new(),
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
      {:error, reason, state} -> {:stop, {:write_error, reason}, {:error, reason}, state}
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

  # The reference makes a message from an already-cancelled timer identifiable,
  # so it cannot clear the bookkeeping of the timer that replaced it.
  def handle_info({@retry_message, reference}, %{retry_timer: {reference, _timer}} = state) do
    state = %{state | retry_timer: nil}
    if is_map(state.rings), do: drain_or_stop(state), else: {:noreply, state}
  end

  def handle_info({@retry_message, _stale_reference}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _owner, reason}, %{owner_monitor: monitor} = state) do
    {:stop, {:owner_down, reason}, state}
  end

  # An orderly stop, so terminate/2 runs and the reverse paths go with it.
  def handle_info({:EXIT, owner, reason}, %{owner: owner} = state) do
    {:stop, {:shutdown, {:owner_exit, reason}}, state}
  end

  def handle_info({:EXIT, _linked, :normal}, state), do: {:noreply, state}

  def handle_info({:EXIT, _linked, reason}, state), do: {:stop, reason, state}

  # The writer is the last part of a connection to stop, so it is the last
  # thing that can record a reverse path for it. Forgetting them here means a
  # note made during teardown cannot outlive the queue it points at.
  @impl true
  def terminate(_reason, %{owner: owner}) do
    ReversePaths.forget_connection(owner)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp drain_or_stop(state) do
    case state |> cancel_retry() |> drain() do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:stop, {:write_error, reason}, state}
    end
  end

  defp drain(state), do: drain(state, @max_drain_per_wake)

  defp drain(state, 0) do
    send(self(), @wake_message)
    {:ok, state}
  end

  defp drain(state, budget) do
    case take_next(state) do
      {{:ok, message, queue_age_microseconds}, state} ->
        # Go counts a pong and a peer-gone frame as it hands them to the
        # writer, and a relayed packet only once the write returned, so the
        # counters are incremented on the same side of the socket call here.
        record_dispatch(state.metrics, message)

        # And the reverse path is recorded before the write, as Go records its
        # watcher before writing: a source that leaves while this write is in
        # flight still owes this destination a peer-gone frame.
        state = note_reverse_path(state, message)

        with {:ok, frame} <- Body.encode_server(message),
             :ok <- send_data(state, frame) do
          record_queue_duration(state.metrics, message, queue_age_microseconds)
          record_send(state.metrics, message)
          drain(state, budget - 1)
        else
          {:error, reason} ->
            :ok = Metrics.add(state.metrics, :write_errors, 1)
            record_write_drop(state.metrics, message)
            {:error, reason, state}
        end

      {:empty, state} ->
        {:ok, state}

      {:busy, state} ->
        {:ok, schedule_retry(state)}

      {:closed, state} ->
        {:ok, state}
    end
  end

  # A producer holds the ring lock. It signals the wake flag under that lock, so
  # a wakeup is only guaranteed when the flag was clear; when it was already set
  # by the wakeup being handled right now, this timer is the one that comes back.
  defp schedule_retry(%{retry_timer: nil} = state) do
    reference = make_ref()
    timer = Process.send_after(self(), {@retry_message, reference}, @retry_interval_ms)
    %{state | retry_timer: {reference, timer}}
  end

  defp schedule_retry(state), do: state

  # The drain that is starting supersedes an earlier retry, so the writer keeps
  # at most one outstanding retry and never accumulates timer messages.
  defp cancel_retry(%{retry_timer: nil} = state), do: state

  defp cancel_retry(%{retry_timer: {reference, timer}} = state) do
    if Process.cancel_timer(timer) == false do
      receive do
        {@retry_message, ^reference} -> :ok
      after
        0 -> :ok
      end
    end

    %{state | retry_timer: nil}
  end

  # Go's sendLoop selects at random among the ready channels, and its lifecycle
  # channels are in that same select: no class is preferred and none can be
  # starved. A cursor rotating over the four classes is the deterministic form
  # of that fairness. Picking the oldest ready head instead would drain a full
  # ordinary ring before a pong that arrived after it.
  defp take_next(state) do
    take_in_order(state, rotation(state.packet_cursor), :empty)
  end

  defp rotation(cursor) do
    Enum.drop(@packet_classes, cursor) ++ Enum.take(@packet_classes, cursor)
  end

  defp take_in_order(state, [], outcome), do: {outcome, state}

  defp take_in_order(state, [class | rest], outcome) do
    case Outbox.take_with_age(Map.fetch!(state.rings, class)) do
      {:ok, _message, _age} = result ->
        {result, %{state | packet_cursor: next_cursor(class)}}

      :empty ->
        take_in_order(state, rest, outcome)

      other ->
        take_in_order(state, rest, weaker_of(outcome, other))
    end
  end

  defp next_cursor(class) do
    rem(Enum.find_index(@packet_classes, &(&1 == class)) + 1, length(@packet_classes))
  end

  # A ring that was locked matters more than one that was closed: the locked one
  # still owes the writer a drain.
  defp weaker_of(:busy, _other), do: :busy
  defp weaker_of(_outcome, other), do: other

  # Go's sawSrc, with one difference: a source is forgotten again when its
  # peer-gone frame is written, so a peer that leaves and returns is owed a
  # second peer-gone. Go never re-arms, which it can afford because its watcher
  # set dies with the connection.
  defp note_reverse_path(state, {:recv_packet, <<0::256>>, _packet}), do: state

  defp note_reverse_path(state, {:recv_packet, source, _packet}) do
    if MapSet.member?(state.noted_sources, source) do
      state
    else
      :ok = Cardinality.insert(state.sender_cardinality, source)
      :ok = Router.note_send(source, state.owner, state.rings.lifecycle)
      %{state | noted_sources: MapSet.put(state.noted_sources, source)}
    end
  end

  # Only a disconnect re-arms. Reason 0x01 says the packet's destination is not
  # here, which is about a key this connection sent to, not about a source it
  # was written packets from.
  defp note_reverse_path(state, {:peer_gone, key, 0x00}) do
    %{state | noted_sources: MapSet.delete(state.noted_sources, key)}
  end

  defp note_reverse_path(state, _message), do: state

  defp record_send(metrics, {:recv_packet, _source, packet}) do
    :ok = Metrics.add(metrics, :packets_sent, 1)
    Metrics.add(metrics, :bytes_sent, byte_size(packet))
  end

  defp record_send(_metrics, _message), do: :ok

  defp record_dispatch(metrics, {:pong, _payload}), do: Metrics.add(metrics, :sent_pong, 1)

  defp record_dispatch(metrics, {:peer_gone, _key, 0x00}),
    do: Metrics.add(metrics, :peer_gone_disconnected_frames, 1)

  defp record_dispatch(metrics, {:peer_gone, _key, _reason}),
    do: Metrics.add(metrics, :peer_gone_not_here_frames, 1)

  defp record_dispatch(_metrics, _message), do: :ok

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

  # The pinned Go client reads WebSocket messages with a 32 KB limit, so a
  # 64 KB DERP frame has to arrive as several messages. The split happens over
  # the iodata: only the binary straddling a chunk boundary is divided, and
  # into sub-binaries, so no relayed packet is ever copied.
  defp send_data(%{wire_mode: :websocket} = state, data) do
    data
    |> :erlang.iolist_to_iovec()
    |> send_websocket_chunks(state)
  end

  defp send_websocket_chunks(iovec, state) do
    {chunk, rest} = take_chunk(iovec, @websocket_chunk_size, [])

    case state.transport.send(state.socket, WebSocketFrame.encode_binary(chunk)) do
      :ok -> if rest == [], do: :ok, else: send_websocket_chunks(rest, state)
      {:error, _reason} = error -> error
    end
  end

  defp take_chunk([], _remaining, taken), do: {Enum.reverse(taken), []}
  defp take_chunk(rest, 0, taken), do: {Enum.reverse(taken), rest}

  defp take_chunk([binary | rest], remaining, taken) when byte_size(binary) <= remaining do
    take_chunk(rest, remaining - byte_size(binary), [binary | taken])
  end

  defp take_chunk([binary | rest], remaining, taken) do
    <<head::binary-size(^remaining), tail::binary>> = binary
    {Enum.reverse([head | taken]), [tail | rest]}
  end
end
