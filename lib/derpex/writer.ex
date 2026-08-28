defmodule Derpex.Writer do
  @moduledoc "The sole socket writer for one DERP connection."

  use GenServer

  alias Derpex.Frame.Body
  alias Derpex.Outbox.Ring

  @wake_message :derpex_outbox_ready

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
       rings: nil
     }}
  end

  @impl true
  def handle_call({:attach, rings}, _from, %{rings: nil} = state) do
    {:reply, :ok, %{state | rings: rings}}
  end

  def handle_call({:control, data}, _from, state) do
    {:reply, state.transport.send(state.socket, data), state}
  end

  @impl true
  def handle_info(@wake_message, %{rings: rings} = state) when is_map(rings) do
    case drain(state) do
      {:ok, state} -> {:noreply, state}
      {:error, reason, state} -> {:stop, {:write_error, reason}, state}
    end
  end

  def handle_info(@wake_message, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _owner, reason}, %{owner_monitor: monitor} = state) do
    {:stop, {:owner_down, reason}, state}
  end

  defp drain(state) do
    case take_next(state.rings) do
      {:ok, message} ->
        with {:ok, frame} <- Body.encode_server(message),
             :ok <- state.transport.send(state.socket, frame) do
          maybe_note_send(state, message)
          drain(state)
        else
          {:error, reason} -> {:error, reason, state}
        end

      :empty ->
        {:ok, state}

      :busy ->
        send(self(), @wake_message)
        {:ok, state}

      :closed ->
        {:ok, state}
    end
  end

  defp take_next(%{lifecycle: lifecycle} = rings) do
    case Ring.take(lifecycle) do
      :empty -> take_packet(rings)
      result -> result
    end
  end

  defp take_packet(%{ordinary: ordinary, disco: disco, pong: pong}) do
    case Ring.take(ordinary) do
      :empty ->
        case Ring.take(disco) do
          :empty -> Ring.take(pong)
          result -> result
        end

      result ->
        result
    end
  end

  defp maybe_note_send(state, {:recv_packet, source, _packet}) do
    Derpex.Router.note_send(source, state.owner, state.rings.lifecycle)
  end

  defp maybe_note_send(_state, _message), do: :ok
end
