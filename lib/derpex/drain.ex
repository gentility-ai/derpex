defmodule Derpex.Drain do
  @moduledoc """
  Coordinates bounded, reversible home-connection drain.

  The baseline profile never emits the non-baseline `FrameRestarting`. The
  Gentility profile may enqueue one notice per current home connection, then a
  single deadline timer closes only the connections that have not relinquished
  home status.
  """

  use GenServer

  alias Derpex.Clock
  require Derpex.Outbox

  alias Derpex.Outbox

  @default_reconnect_ms 1_000
  @default_try_for_ms 10_000
  @default_jitter_ms 5_000
  @default_deadline_ms 30_000
  @maximum_duration_ms 86_400_000
  @maximum_frame_value 0xFFFF_FFFF

  @type profile :: :baseline | :gentility

  @doc false
  def start_link(options \\ []) do
    {name, options} = Keyword.pop(options, :name, __MODULE__)
    GenServer.start_link(__MODULE__, options, if(name, do: [name: name], else: []))
  end

  @doc "Registers an ordinary authenticated connection. Mesh peers are exempt."
  @spec register(GenServer.server() | nil, pid(), Outbox.t(), boolean()) :: :ok
  def register(server \\ __MODULE__, connection, lifecycle, mesh_peer? \\ false)

  def register(nil, _connection, _lifecycle, _mesh_peer?), do: :ok
  def register(_server, _connection, _lifecycle, true), do: :ok

  def register(server, connection, lifecycle, false)
      when is_pid(connection) and Outbox.is_outbox(lifecycle) do
    GenServer.call(server, {:register, connection, lifecycle})
  end

  @doc "Removes a connection explicitly; process monitoring repairs missed cleanup."
  @spec unregister(GenServer.server() | nil, pid()) :: :ok
  def unregister(server \\ __MODULE__, connection \\ self())

  def unregister(nil, _connection), do: :ok

  def unregister(server, connection) do
    GenServer.call(server, {:unregister, connection})
  catch
    :exit, _reason -> :ok
  end

  @doc "Records home status, rejecting a transition to home while draining."
  @spec set_preferred(GenServer.server() | nil, pid(), boolean()) ::
          :ok | {:error, :draining}
  def set_preferred(server \\ __MODULE__, connection \\ self(), preferred)

  def set_preferred(nil, _connection, _preferred), do: :ok

  def set_preferred(server, connection, preferred)
      when is_pid(connection) and is_boolean(preferred) do
    GenServer.call(server, {:set_preferred, connection, preferred})
  end

  @doc "Starts a drain once; repeated calls return the active drain unchanged."
  @spec begin_drain(GenServer.server(), keyword()) :: {:ok, map()}
  def begin_drain(server \\ __MODULE__, options \\ []) do
    GenServer.call(server, {:begin_drain, options})
  end

  @doc "Rolls back an active drain and permits home transitions again."
  @spec cancel(GenServer.server()) :: :ok
  def cancel(server \\ __MODULE__), do: GenServer.call(server, :cancel)

  @doc "Closes every remaining drain target immediately. Idempotent."
  @spec finish(GenServer.server()) :: {:ok, non_neg_integer()}
  def finish(server \\ __MODULE__), do: GenServer.call(server, :finish)

  @doc "Returns bounded state without node, organization, or source attribution."
  @spec stats(GenServer.server()) :: map()
  def stats(server \\ __MODULE__), do: GenServer.call(server, :stats)

  @impl true
  def init(options) do
    profile = Keyword.get(options, :profile, :baseline)

    unless profile in [:baseline, :gentility] do
      raise ArgumentError, "profile must be :baseline or :gentility"
    end

    {:ok,
     %{
       profile: profile,
       clock: Keyword.get(options, :clock, Clock),
       jitter: Keyword.get(options, :jitter, fn maximum -> :rand.uniform(maximum + 1) - 1 end),
       connections: %{},
       monitors: %{},
       draining?: false,
       drain_token: nil,
       deadline_timer: nil,
       deadline_at: nil,
       targets: MapSet.new(),
       reconnect_ms: nil,
       try_for_ms: nil,
       notifications_enqueued: 0,
       notification_drops: 0,
       deadline_closes: 0
     }}
  end

  @impl true
  def handle_call({:register, connection, lifecycle}, _from, state) do
    state = remove_connection(state, connection, true)
    monitor = Process.monitor(connection)

    state = %{
      state
      | connections:
          Map.put(state.connections, connection, %{lifecycle: lifecycle, home?: false}),
        monitors: Map.put(state.monitors, connection, monitor)
    }

    {:reply, :ok, state}
  end

  def handle_call({:unregister, connection}, _from, state) do
    {:reply, :ok, remove_connection(state, connection, true)}
  end

  def handle_call({:set_preferred, connection, true}, _from, %{draining?: true} = state) do
    if Map.has_key?(state.connections, connection) do
      {:reply, {:error, :draining}, state}
    else
      {:reply, :ok, state}
    end
  end

  def handle_call({:set_preferred, connection, preferred}, _from, state) do
    state =
      case state.connections[connection] do
        nil ->
          state

        entry ->
          entry = %{entry | home?: preferred}

          %{
            state
            | connections: Map.put(state.connections, connection, entry),
              targets:
                if(preferred,
                  do: state.targets,
                  else: MapSet.delete(state.targets, connection)
                )
          }
      end

    {:reply, :ok, state}
  end

  def handle_call({:begin_drain, _options}, _from, %{draining?: true} = state) do
    {:reply, {:ok, drain_info(state)}, state}
  end

  def handle_call({:begin_drain, options}, _from, state) do
    config = drain_config!(options)
    token = make_ref()
    targets = home_connections(state.connections)
    {enqueued, dropped} = notify_targets(state, targets, config)

    deadline_timer =
      state.clock.send_after(self(), {__MODULE__, :deadline, token}, config.deadline_ms)

    state = %{
      state
      | draining?: true,
        drain_token: token,
        deadline_timer: deadline_timer,
        deadline_at: state.clock.monotonic_time(:millisecond) + config.deadline_ms,
        targets: targets,
        reconnect_ms: config.reconnect_ms,
        try_for_ms: config.try_for_ms,
        notifications_enqueued: state.notifications_enqueued + enqueued,
        notification_drops: state.notification_drops + dropped
    }

    {:reply, {:ok, drain_info(state)}, state}
  end

  def handle_call(:cancel, _from, state) do
    cancel_timer(state)

    state = %{
      state
      | draining?: false,
        drain_token: nil,
        deadline_timer: nil,
        deadline_at: nil,
        targets: MapSet.new(),
        reconnect_ms: nil,
        try_for_ms: nil
    }

    {:reply, :ok, state}
  end

  def handle_call(:finish, _from, state) do
    {closed, state} = close_targets(state)
    {:reply, {:ok, closed}, state}
  end

  def handle_call(:stats, _from, state), do: {:reply, stats_from(state), state}

  @impl true
  def handle_info({__MODULE__, :deadline, token}, %{drain_token: token} = state) do
    {_closed, state} = close_targets(%{state | deadline_timer: nil})
    {:noreply, state}
  end

  def handle_info({__MODULE__, :deadline, _stale}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, connection, _reason}, state) do
    case state.monitors[connection] do
      ^monitor -> {:noreply, remove_connection(state, connection, false)}
      _stale -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    cancel_timer(state)
    :ok
  end

  defp notify_targets(%{profile: :baseline}, _targets, _config), do: {0, 0}
  defp notify_targets(_state, _targets, %{notify?: false}), do: {0, 0}

  defp notify_targets(state, targets, config) do
    Enum.reduce(targets, {0, 0}, fn connection, {enqueued, dropped} ->
      %{lifecycle: lifecycle} = Map.fetch!(state.connections, connection)

      reconnect_ms =
        min(config.reconnect_ms + jitter(state.jitter, config.jitter_ms), @maximum_frame_value)

      # The coordinator notifies every home connection in one call, so it never
      # naps on one connection's ring lock while the rest wait.
      notice = {:restarting, reconnect_ms, config.try_for_ms}

      case Outbox.enqueue(lifecycle, notice, wait: false) do
        {:ok, _result} -> {enqueued + 1, dropped}
        {:dropped, _reason} -> {enqueued, dropped + 1}
      end
    end)
  end

  defp jitter(_function, 0), do: 0

  defp jitter(function, maximum) do
    function.(maximum)
    |> max(0)
    |> min(maximum)
  end

  defp home_connections(connections) do
    Enum.reduce(connections, MapSet.new(), fn
      {connection, %{home?: true}}, targets -> MapSet.put(targets, connection)
      {_connection, %{home?: false}}, targets -> targets
    end)
  end

  defp remove_connection(state, connection, demonitor?) do
    case Map.pop(state.monitors, connection) do
      {nil, _monitors} ->
        state

      {monitor, monitors} ->
        if demonitor?, do: Process.demonitor(monitor, [:flush])

        %{
          state
          | monitors: monitors,
            connections: Map.delete(state.connections, connection),
            targets: MapSet.delete(state.targets, connection)
        }
    end
  end

  defp cancel_timer(%{deadline_timer: nil}), do: :ok

  defp cancel_timer(state) do
    _remaining = state.clock.cancel_timer(state.deadline_timer)
    :ok
  end

  defp close_targets(state) do
    cancel_timer(state)
    closed = MapSet.size(state.targets)
    Enum.each(state.targets, &send(&1, {:derpex_drain_close, state.drain_token}))

    state = %{
      state
      | deadline_timer: nil,
        deadline_at: nil,
        deadline_closes: state.deadline_closes + closed,
        targets: MapSet.new()
    }

    {closed, state}
  end

  defp drain_config!(options) when is_list(options) do
    reconnect_ms = duration!(options, :reconnect_ms, @default_reconnect_ms, @maximum_frame_value)
    try_for_ms = duration!(options, :try_for_ms, @default_try_for_ms, @maximum_frame_value)
    jitter_ms = duration!(options, :jitter_ms, @default_jitter_ms, @maximum_frame_value)
    deadline_ms = duration!(options, :deadline_ms, @default_deadline_ms, @maximum_duration_ms)
    notify? = Keyword.get(options, :notify?, true)

    unless is_boolean(notify?), do: raise(ArgumentError, "notify? must be boolean")

    if reconnect_ms + jitter_ms > @maximum_frame_value do
      raise ArgumentError, "reconnect_ms plus jitter_ms exceeds the DERP frame limit"
    end

    %{
      reconnect_ms: reconnect_ms,
      try_for_ms: try_for_ms,
      jitter_ms: jitter_ms,
      deadline_ms: deadline_ms,
      notify?: notify?
    }
  end

  defp drain_config!(_invalid), do: raise(ArgumentError, "drain options must be a keyword list")

  defp duration!(options, key, default, maximum) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value >= 0 and value <= maximum -> value
      _invalid -> raise ArgumentError, "#{key} is outside its supported range"
    end
  end

  defp drain_info(state) do
    %{
      draining?: state.draining?,
      targeted_connections: MapSet.size(state.targets),
      reconnect_ms: state.reconnect_ms,
      try_for_ms: state.try_for_ms
    }
  end

  defp stats_from(state) do
    home_connections = Enum.count(state.connections, fn {_pid, entry} -> entry.home? end)

    %{
      profile: state.profile,
      draining?: state.draining?,
      accepting_home?: not state.draining?,
      connections: map_size(state.connections),
      home_connections: home_connections,
      targeted_connections: MapSet.size(state.targets),
      deadline_remaining_ms: deadline_remaining(state),
      notifications_enqueued: state.notifications_enqueued,
      notification_drops: state.notification_drops,
      deadline_closes: state.deadline_closes
    }
  end

  defp deadline_remaining(%{deadline_at: nil}), do: nil

  defp deadline_remaining(state) do
    max(state.deadline_at - state.clock.monotonic_time(:millisecond), 0)
  end
end
