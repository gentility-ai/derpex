defmodule Derpex.Router do
  @moduledoc """
  Serializes connection topology while keeping successful packet routing in ETS.

  `route/3` never calls this GenServer. It performs one protected-table lookup
  and publishes directly into the destination's bounded ring.
  """

  use GenServer

  alias Derpex.Disco
  alias Derpex.Metrics
  require Derpex.Outbox

  alias Derpex.Outbox
  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Ring
  alias Derpex.Router.ReversePaths

  @table __MODULE__.Routes
  @registrations_table __MODULE__.Registrations
  @duplicates_table __MODULE__.Duplicates
  @forwarders_table __MODULE__.Forwarders

  # Each registration owns one atomics array: slot 1 orders duplicate
  # connections by last activity, slot 2 is Go's `sclient.isDup`. A connection
  # that is not a duplicate can never win a promotion, so it reads slot 2 and
  # skips the tables entirely.
  @activity_slot 1
  @duplicate_slot 2
  @activity_cache __MODULE__.CachedActivity

  # A snapshot of a busy region is tens of thousands of frames; this is how many
  # the router publishes before serving anything else.
  @snapshot_chunk 1_024
  @snapshot_pause_ms 5
  # Frames that lost their watcher's queue lock, retried in order.
  @pending_table __MODULE__.PendingLifecycle
  @flush_budget 256
  @flush_retry_ms 1

  @default_presence %{
    ip: <<0::128>>,
    port: 0,
    flags: 0x01,
    app_name: ""
  }

  @type route_result ::
          Ring.enqueue_result() | {:dropped, :unknown_destination | :closed_destination}
  @type presence :: %{
          required(:ip) => <<_::128>>,
          required(:port) => 0..65_535,
          required(:flags) => 0..255,
          required(:app_name) => binary()
        }

  @doc false
  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc "Makes a connection the active local route for its node key."
  @spec register(binary(), pid(), Ring.t()) :: :ok
  def register(<<key::binary-size(32)>>, connection, %Ring{} = ring) when is_pid(connection) do
    register(key, connection, ring, ring, ring)
  end

  @doc "Makes a connection active with separate packet and lifecycle rings."
  @spec register(binary(), pid(), Ring.t(), Ring.t()) :: :ok
  def register(
        <<key::binary-size(32)>>,
        connection,
        %Ring{} = ordinary,
        lifecycle
      )
      when is_pid(connection) and Outbox.is_outbox(lifecycle) do
    register(key, connection, ordinary, ordinary, lifecycle)
  end

  @doc "Makes a connection active with separate ordinary, disco, and lifecycle rings."
  @spec register(binary(), pid(), Ring.t(), Ring.t(), Ring.t()) :: :ok
  def register(
        <<key::binary-size(32)>>,
        connection,
        %Ring{} = ordinary,
        %Ring{} = disco,
        lifecycle
      )
      when is_pid(connection) and Outbox.is_outbox(lifecycle) do
    register(key, connection, ordinary, disco, lifecycle, @default_presence)
  end

  @doc "Makes a connection active and publishes its watcher-presence metadata."
  @spec register(binary(), pid(), Ring.t(), Ring.t(), Ring.t(), presence()) :: :ok
  def register(
        <<key::binary-size(32)>>,
        connection,
        %Ring{} = ordinary,
        %Ring{} = disco,
        lifecycle,
        %{
          ip: <<_ip::binary-size(16)>>,
          port: port,
          flags: flags,
          app_name: app_name
        } = presence
      )
      when is_pid(connection) and port in 0..65_535 and flags in 0..255 and
             is_binary(app_name) and Outbox.is_outbox(lifecycle) do
    {:ok, activity} =
      GenServer.call(
        __MODULE__,
        {:register, key, connection, ordinary, disco, lifecycle, presence}
      )

    cache_activity(key, connection, activity)
  end

  @doc "Removes a connection only if it is still the active route."
  @spec unregister(binary(), pid()) :: :ok
  def unregister(<<key::binary-size(32)>>, connection) when is_pid(connection) do
    GenServer.call(__MODULE__, {:unregister, key, connection})
  end

  @doc "Subscribes a trusted connection to the current snapshot and future presence changes."
  @spec watch(pid(), Ring.t()) :: :ok
  def watch(connection, lifecycle) when is_pid(connection) and Outbox.is_outbox(lifecycle) do
    GenServer.call(__MODULE__, {:watch, connection, lifecycle})
  end

  @doc "Asks every local connection for a node key to close."
  @spec close_peer(binary()) :: non_neg_integer()
  def close_peer(<<key::binary-size(32)>>) do
    GenServer.call(__MODULE__, {:close_peer, key})
  end

  @doc "Registers a bounded regional forwarding path for a node key."
  @spec add_forwarder(binary(), term(), Ring.t()) :: :ok
  def add_forwarder(<<key::binary-size(32)>>, identity, %Ring{} = ring) do
    GenServer.call(__MODULE__, {:add_forwarder, key, identity, ring})
  end

  @doc "Removes a regional forwarding path if the identity is registered."
  @spec remove_forwarder(binary(), term()) :: :ok
  def remove_forwarder(<<key::binary-size(32)>>, identity) do
    GenServer.call(__MODULE__, {:remove_forwarder, key, identity})
  end

  @doc "Returns the number of regional paths registered for a node key."
  @spec forwarder_count(binary()) :: non_neg_integer()
  def forwarder_count(<<key::binary-size(32)>>) do
    GenServer.call(__MODULE__, {:forwarder_count, key})
  end

  @doc "Publishes to the active local route, then a regional forwarder on a miss."
  @spec route(binary(), binary(), binary()) :: route_result()
  def route(<<source::binary-size(32)>>, <<destination::binary-size(32)>>, packet)
      when is_binary(packet) do
    case route_local(source, destination, packet) do
      {:dropped, :unknown_destination} -> route_forwarder(source, destination, packet)
      result -> result
    end
  end

  @doc "Publishes only to a local route, preventing an already-forwarded packet from looping."
  @spec route_local(binary(), binary(), binary()) :: route_result()
  def route_local(<<source::binary-size(32)>>, <<destination::binary-size(32)>>, packet)
      when is_binary(packet) do
    case :ets.lookup(@table, destination) do
      [{^destination, _connection, ordinary, disco, _lifecycle}] ->
        ring = if Disco.looks_like_wrapper?(packet), do: disco, else: ordinary
        safe_enqueue(ring, {:recv_packet, source, packet})

      [] ->
        {:dropped, :unknown_destination}
    end
  end

  @doc "Records a reverse path after the destination writer emits a packet."
  @spec note_send(binary(), pid(), Ring.t()) :: :ok
  def note_send(<<source::binary-size(32)>>, destination_connection, lifecycle)
      when is_pid(destination_connection) and Outbox.is_outbox(lifecycle) do
    ReversePaths.note(source, destination_connection, lifecycle)
  end

  @doc """
  Promotes a duplicate connection when it is the latest one to send a frame.

  Called for every client frame, so the common case must stay off the tables.
  `register/6` leaves the caller's own activity handle in its process
  dictionary, which turns the sole-connection case into one atomics read.
  """
  @spec note_activity(binary(), pid()) :: :ok
  def note_activity(<<key::binary-size(32)>>, connection) when is_pid(connection) do
    case Process.get(@activity_cache) do
      {^key, ^connection, activity} -> promote_cached_duplicate(key, connection, activity)
      _uncached -> promote_duplicate(key, connection)
    end
  end

  defp cache_activity(key, connection, activity) do
    if connection == self() do
      Process.put(@activity_cache, {key, connection, activity})
    end

    :ok
  end

  defp promote_cached_duplicate(key, connection, activity) do
    case :atomics.get(activity, @duplicate_slot) do
      0 -> :ok
      _duplicate -> promote_duplicate(key, connection)
    end
  end

  defp promote_duplicate(key, connection) do
    with [{^key}] <- :ets.lookup(@duplicates_table, key),
         [{{^key, ^connection}, ordinary, {disco, lifecycle}, activity}] <-
           :ets.lookup(@registrations_table, {key, connection}) do
      :atomics.put(activity, @activity_slot, activity_sequence())
      true = :ets.insert(@table, {key, connection, ordinary, disco, lifecycle})
    end

    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc "Returns the active route count for assertions and telemetry."
  @spec route_count() :: non_neg_integer()
  def route_count, do: :ets.info(@table, :size)

  @doc "Returns aggregate topology gauges without client identifiers."
  @spec stats() :: map()
  def stats, do: GenServer.call(__MODULE__, :stats)

  @doc false
  @spec debug_client_keys() :: %{optional({:inet.ip_address(), 0..65_535}) => binary()}
  def debug_client_keys, do: GenServer.call(__MODULE__, :debug_client_keys)

  @doc "Checks that serialized topology and fast-path tables agree."
  @spec consistency_check() :: :ok | {:error, binary()}
  def consistency_check, do: GenServer.call(__MODULE__, :consistency_check)

  @doc "Returns the active route's writer without calling the topology process."
  @spec active_writer(binary()) :: {:ok, pid()} | {:error, :not_connected}
  def active_writer(<<key::binary-size(32)>>) do
    case :ets.lookup(@table, key) do
      [{^key, _connection, %Ring{notifier: writer}, _disco, _lifecycle}]
      when is_pid(writer) ->
        {:ok, writer}

      [] ->
        {:error, :not_connected}
    end
  rescue
    ArgumentError -> {:error, :not_connected}
  end

  @impl true
  def init(_options) do
    table =
      :ets.new(@table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true
      ])

    :ok = ReversePaths.new()

    _pending_table =
      :ets.new(@pending_table, [
        :named_table,
        :ordered_set,
        :public
      ])

    registrations_table =
      :ets.new(@registrations_table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    duplicates_table =
      :ets.new(@duplicates_table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true
      ])

    forwarders_table =
      :ets.new(@forwarders_table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true
      ])

    {:ok,
     %{
       table: table,
       registrations_table: registrations_table,
       duplicates_table: duplicates_table,
       forwarders_table: forwarders_table,
       watchers: %{},
       snapshots: %{},
       monitors: %{},
       forwarder_monitors: %{},
       routes: %{},
       forwarders: %{}
     }}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    {:reply, topology_stats(state), state}
  end

  def handle_call(:debug_client_keys, _from, state) do
    {:reply, debug_client_keys(state.routes), state}
  end

  def handle_call(:consistency_check, _from, state) do
    {:reply, check_consistency(state), state}
  end

  def handle_call(
        {:register, key, connection, ordinary, disco, lifecycle, presence},
        _from,
        state
      ) do
    {monitor, monitors} = ensure_monitor(state.monitors, connection)
    activity = :atomics.new(2, signed: false)
    :atomics.put(activity, @activity_slot, activity_sequence())

    previous_entries = Map.get(state.routes, key, [])

    entries =
      previous_entries
      |> Enum.reject(fn {
                          registered_connection,
                          _ordinary,
                          _disco,
                          _lifecycle,
                          _activity,
                          _presence
                        } ->
        registered_connection == connection
      end)
      |> Kernel.++([{connection, ordinary, disco, lifecycle, activity, presence}])

    if previous_entries != [] do
      :ok = Metrics.add(Metrics.default_handle(), :counter_total_dup_client_conns, 1)
    end

    true =
      :ets.insert(
        @registrations_table,
        {{key, connection}, ordinary, {disco, lifecycle}, activity}
      )

    update_duplicate_marker(key, entries)
    true = :ets.insert(@table, {key, connection, ordinary, disco, lifecycle})

    broadcast(
      state.watchers,
      {:peer_present, key, presence.ip, presence.port, presence.flags, presence.app_name}
    )

    monitors =
      Map.put(monitors, connection, {monitor, MapSet.put(keys_for(monitors, connection), key)})

    {:reply, {:ok, activity},
     %{state | monitors: monitors, routes: Map.put(state.routes, key, entries)}}
  end

  def handle_call({:unregister, key, connection}, _from, state) do
    had_key? = Map.has_key?(state.routes, key)
    routes = remove_route(state.routes, key, connection, state.forwarders)
    monitors = remove_connection_key(state.monitors, connection, key)

    if had_key? and not Map.has_key?(routes, key) do
      broadcast(state.watchers, {:peer_gone, key, 0x00})
    end

    forget_destination(connection)
    _forgotten = forget_parked(connection)
    watchers = Map.delete(state.watchers, connection)
    snapshots = Map.delete(state.snapshots, connection)

    {:reply, :ok,
     %{state | monitors: monitors, routes: routes, watchers: watchers, snapshots: snapshots}}
  end

  # The snapshot of a full region is tens of thousands of frames. Sending it
  # from inside this call would hold the router for all of them and would
  # overflow a watcher whose queue is already near its cap, so the keys are
  # remembered and streamed a chunk at a time, between everything else the
  # router has to do.
  def handle_call({:watch, connection, lifecycle}, _from, state) do
    {monitor, monitors} = ensure_monitor(state.monitors, connection)
    monitors = Map.put(monitors, connection, {monitor, keys_for(monitors, connection)})
    send(self(), {:snapshot_chunk, connection})

    {:reply, :ok,
     %{
       state
       | monitors: monitors,
         watchers: Map.put(state.watchers, connection, lifecycle),
         snapshots: Map.put(state.snapshots, connection, Map.keys(state.routes))
     }}
  end

  def handle_call({:close_peer, key}, _from, state) do
    connections =
      state.routes
      |> Map.get(key, [])
      |> Enum.map(fn {connection, _ordinary, _disco, _lifecycle, _activity, _presence} ->
        connection
      end)

    Enum.each(connections, &send(&1, {:derpex_close_peer, key}))
    {:reply, length(connections), state}
  end

  def handle_call({:add_forwarder, key, identity, ring}, _from, state) do
    entries = Map.get(state.forwarders, key, [])

    if Enum.any?(entries, fn {registered_identity, _ring, _sequence} ->
         registered_identity == identity
       end) do
      {:reply, :ok, replace_forwarder_ring(state, key, entries, identity, ring)}
    else
      entries = entries ++ [{identity, ring, activity_sequence()}]
      publish_preferred_forwarder(key, entries)
      forwarder_monitors = add_forwarder_monitor(state.forwarder_monitors, identity, key)

      {:reply, :ok,
       %{
         state
         | forwarders: Map.put(state.forwarders, key, entries),
           forwarder_monitors: forwarder_monitors
       }}
    end
  end

  def handle_call({:remove_forwarder, key, identity}, _from, state) do
    case Map.fetch(state.forwarders, key) do
      {:ok, registered} ->
        {:reply, :ok, drop_forwarder(state, key, identity, registered)}

      :error ->
        note_remove_forwarder_other()
        {:reply, :ok, state}
    end
  end

  def handle_call({:forwarder_count, key}, _from, state) do
    {:reply, state.forwarders |> Map.get(key, []) |> length(), state}
  end

  @impl true
  def handle_info(:derpex_flush_lifecycle, state) do
    :ok = flush_parked(@flush_budget)
    {:noreply, state}
  end

  def handle_info({:snapshot_chunk, connection}, state) do
    {:noreply, stream_snapshot(state, connection)}
  end

  def handle_info({:DOWN, monitor, :process, connection, _reason}, state) do
    state = handle_connection_down(state, monitor, connection)
    {:noreply, handle_forwarder_down(state, monitor, connection)}
  end

  defp ensure_monitor(monitors, connection) do
    case monitors[connection] do
      {monitor, _keys} -> {monitor, monitors}
      nil -> {Process.monitor(connection), monitors}
    end
  end

  defp handle_connection_down(state, monitor, connection) do
    case state.monitors[connection] do
      {^monitor, keys} ->
        {routes, gone_keys} =
          remove_connection_routes(state.routes, keys, connection, state.forwarders)

        Enum.each(gone_keys, &broadcast(state.watchers, {:peer_gone, &1, 0x00}))
        forget_destination(connection)
        _forgotten = forget_parked(connection)

        %{
          state
          | monitors: Map.delete(state.monitors, connection),
            routes: routes,
            watchers: Map.delete(state.watchers, connection),
            snapshots: Map.delete(state.snapshots, connection)
        }

      _different_or_missing_monitor ->
        state
    end
  end

  defp handle_forwarder_down(state, monitor, identity) do
    case state.forwarder_monitors[identity] do
      {^monitor, keys} ->
        forwarders =
          Enum.reduce(keys, state.forwarders, fn key, forwarders ->
            remove_dead_forwarder(forwarders, state.routes, key, identity)
          end)

        %{
          state
          | forwarders: forwarders,
            forwarder_monitors: Map.delete(state.forwarder_monitors, identity)
        }

      _different_or_missing_monitor ->
        state
    end
  end

  defp add_forwarder_monitor(monitors, identity, key) when is_pid(identity) do
    case monitors[identity] do
      {monitor, keys} -> Map.put(monitors, identity, {monitor, MapSet.put(keys, key)})
      nil -> Map.put(monitors, identity, {Process.monitor(identity), MapSet.new([key])})
    end
  end

  defp add_forwarder_monitor(monitors, _identity, _key), do: monitors

  defp remove_forwarder_monitor(monitors, identity, key) when is_pid(identity) do
    case monitors[identity] do
      {monitor, keys} ->
        keys = MapSet.delete(keys, key)

        if MapSet.size(keys) == 0 do
          Process.demonitor(monitor, [:flush])
          Map.delete(monitors, identity)
        else
          Map.put(monitors, identity, {monitor, keys})
        end

      nil ->
        monitors
    end
  end

  defp remove_forwarder_monitor(monitors, _identity, _key), do: monitors

  defp drop_forwarder(state, key, identity, registered) do
    entries =
      Enum.reject(registered, fn {registered_identity, _ring, _sequence} ->
        registered_identity == identity
      end)

    if length(entries) == length(registered) do
      note_remove_forwarder_other()
      state
    else
      publish_preferred_forwarder(key, entries)

      %{
        state
        | forwarders: store_forwarders(state.forwarders, state.routes, key, entries),
          forwarder_monitors: remove_forwarder_monitor(state.forwarder_monitors, identity, key)
      }
    end
  end

  # Go's `removePktForwardOther`: a removal naming a forwarder the map never
  # held. Go counts only the unknown-identity case because an unknown key
  # returns before its accounting; DERPEX keeps a single list per key, so both
  # misses are the same bookkeeping drift and both are counted here.
  defp note_remove_forwarder_other do
    :ok = Metrics.add(Metrics.default_handle(), :remove_forwarder_other, 1)
  end

  defp remove_dead_forwarder(forwarders, routes, key, identity) do
    entries =
      forwarders
      |> Map.get(key, [])
      |> Enum.reject(fn {registered_identity, _ring, _sequence} ->
        registered_identity == identity
      end)

    publish_preferred_forwarder(key, entries)
    store_forwarders(forwarders, routes, key, entries)
  end

  defp store_forwarders(forwarders, routes, key, []) do
    note_peer_gone_from_region(key, Map.has_key?(routes, key))
    Map.delete(forwarders, key)
  end

  defp store_forwarders(forwarders, _routes, key, entries) do
    Map.put(forwarders, key, entries)
  end

  defp keys_for(monitors, connection) do
    case monitors[connection] do
      {_monitor, keys} -> keys
      nil -> MapSet.new()
    end
  end

  defp remove_connection_key(monitors, connection, key) do
    case monitors[connection] do
      {monitor, keys} ->
        keys = MapSet.delete(keys, key)

        if MapSet.size(keys) == 0 do
          Process.demonitor(monitor, [:flush])
          Map.delete(monitors, connection)
        else
          Map.put(monitors, connection, {monitor, keys})
        end

      nil ->
        monitors
    end
  end

  defp remove_connection_routes(routes, keys, connection, forwarders) do
    Enum.reduce(keys, {routes, []}, fn key, {routes, gone_keys} ->
      had_key? = Map.has_key?(routes, key)
      routes = remove_route(routes, key, connection, forwarders)

      if had_key? and not Map.has_key?(routes, key) do
        {routes, [key | gone_keys]}
      else
        {routes, gone_keys}
      end
    end)
  end

  defp remove_route(routes, key, connection, forwarders) do
    true = :ets.delete(@registrations_table, {key, connection})

    {removed, entries} =
      routes
      |> Map.get(key, [])
      |> Enum.split_with(fn {
                              registered_connection,
                              _ordinary,
                              _disco,
                              _lifecycle,
                              _activity,
                              _presence
                            } ->
        registered_connection == connection
      end)

    Enum.each(removed, &mark_duplicate(&1, 0))
    update_duplicate_marker(key, entries)

    case entries do
      [] ->
        true = :ets.delete(@table, key)
        note_peer_gone_from_region(key, Map.has_key?(forwarders, key))
        Map.delete(routes, key)

      _remaining ->
        {active_connection, active_ordinary, active_disco, active_lifecycle, _activity, _presence} =
          Enum.max_by(
            entries,
            fn {_connection, _ordinary, _disco, _lifecycle, activity, _presence} ->
              :atomics.get(activity, 1)
            end
          )

        true =
          :ets.insert(
            @table,
            {key, active_connection, active_ordinary, active_disco, active_lifecycle}
          )

        Map.put(routes, key, entries)
    end
  end

  # Go's `notePeerGoneFromRegionLocked` runs only once the key has left
  # `clientsMesh` entirely: `unregisterClient` drops the entry only when its
  # forwarder is nil, and `RemovePacketForwarder` keeps the entry (as nil) while
  # a local client remains. A peer that still has either path is not gone from
  # the region, so its reverse paths stay recorded for whichever path leaves last.
  defp note_peer_gone_from_region(_key, true = _still_reachable?), do: :ok
  defp note_peer_gone_from_region(key, false = _still_reachable?), do: notify_peer_gone(key)

  # `take/1` has already deleted the rows, so nothing can retry this frame from
  # the reverse-path index: a peer-gone that loses the queue's lock has to be
  # parked like any other presence change, or the destination is left believing
  # a peer it was relaying to is still there.
  defp notify_peer_gone(key) do
    key
    |> ReversePaths.take()
    |> Enum.each(fn {destination_connection, lifecycle} ->
      _enqueue_result =
        notify_enqueue(lifecycle, {:peer_gone, key, 0x00}, destination_connection)
    end)
  end

  defp forget_destination(connection) do
    ReversePaths.forget_connection(connection)
  end

  defp update_duplicate_marker(key, entries) do
    duplicate = if length(entries) > 1, do: 1, else: 0
    Enum.each(entries, &mark_duplicate(&1, duplicate))

    if duplicate == 1 do
      true = :ets.insert(@duplicates_table, {key})
    else
      true = :ets.delete(@duplicates_table, key)
    end
  end

  defp mark_duplicate(
         {_connection, _ordinary, _disco, _lifecycle, activity, _presence},
         duplicate
       ) do
    :atomics.put(activity, @duplicate_slot, duplicate)
  end

  # One chunk per message: the router serves everything else between them, and a
  # watcher that is already behind is waited for rather than overflowed.
  defp stream_snapshot(state, connection) do
    with {:ok, keys} <- Map.fetch(state.snapshots, connection),
         {:ok, lifecycle} <- Map.fetch(state.watchers, connection) do
      send_snapshot_chunk(state, connection, lifecycle, keys)
    else
      :error -> %{state | snapshots: Map.delete(state.snapshots, connection)}
    end
  end

  defp send_snapshot_chunk(state, connection, _lifecycle, []) do
    %{state | snapshots: Map.delete(state.snapshots, connection)}
  end

  defp send_snapshot_chunk(state, connection, lifecycle, keys) do
    chunk_size = snapshot_chunk_size(lifecycle)

    if room_for_snapshot_chunk?(lifecycle, chunk_size) do
      {chunk, rest} = Enum.split(keys, chunk_size)

      state.routes
      |> snapshot_presence(chunk)
      |> Enum.each(fn message ->
        _enqueue_result = notify_enqueue(lifecycle, message, connection)
      end)

      if rest == [] do
        %{state | snapshots: Map.delete(state.snapshots, connection)}
      else
        send(self(), {:snapshot_chunk, connection})
        %{state | snapshots: Map.put(state.snapshots, connection, rest)}
      end
    else
      _timer = Process.send_after(self(), {:snapshot_chunk, connection}, @snapshot_pause_ms)
      state
    end
  rescue
    # The queue dies with its connection, and the DOWN that ends the watch can
    # be behind the chunk message being handled. A watcher that left mid
    # snapshot ends its own stream; it does not take the router with it.
    ArgumentError -> %{state | snapshots: Map.delete(state.snapshots, connection)}
  end

  # A snapshot may fill half the queue; the other half stays free for the
  # presence changes that keep arriving while it streams. Filling the queue to
  # the cap left the next broadcast to overflow it, so a region larger than the
  # soft cap could not onboard a watcher at all — it was closed for connecting.
  # The chunk is capped by the same allowance, so a queue smaller than a chunk
  # is streamed in pieces it can hold rather than waiting for room it can never
  # have.
  defp snapshot_chunk_size(%LifecycleQueue{} = queue),
    do: max(min(@snapshot_chunk, snapshot_allowance(queue)), 1)

  defp snapshot_chunk_size(_ring), do: @snapshot_chunk

  defp room_for_snapshot_chunk?(%LifecycleQueue{} = queue, chunk_size),
    do: LifecycleQueue.size(queue) + chunk_size <= snapshot_allowance(queue)

  defp room_for_snapshot_chunk?(_ring, _chunk_size), do: true

  defp snapshot_allowance(queue), do: max(div(LifecycleQueue.soft_cap(queue), 2), 1)

  defp snapshot_presence(routes, keys) do
    routes
    |> Map.take(keys)
    |> snapshot_presence()
  end

  defp snapshot_presence(routes) do
    Enum.flat_map(routes, fn {key, entries} ->
      case :ets.lookup(@table, key) do
        [{^key, active_connection, _ordinary, _disco, _lifecycle}] ->
          Enum.flat_map(entries, fn
            {^active_connection, _ordinary, _disco, _lifecycle, _activity, presence} ->
              [
                {:peer_present, key, presence.ip, presence.port, presence.flags,
                 presence.app_name}
              ]

            _inactive ->
              []
          end)

        [] ->
          []
      end
    end)
  end

  defp broadcast(watchers, message) do
    Enum.each(watchers, fn {connection, lifecycle} ->
      _enqueue_result = notify_enqueue(lifecycle, message, connection)
    end)

    :ok
  end

  # A re-registering identity brings a fresh ring: a mesh client builds a new
  # one per reconnect and deletes the old. Keeping the ring already on file
  # would publish a table that no longer exists, so swap it in place and leave
  # the sequence alone so preference order does not shift under the swap.
  defp replace_forwarder_ring(state, key, entries, identity, ring) do
    entries =
      Enum.map(entries, fn
        {^identity, _stale_ring, sequence} -> {identity, ring, sequence}
        entry -> entry
      end)

    publish_preferred_forwarder(key, entries)
    %{state | forwarders: Map.put(state.forwarders, key, entries)}
  end

  defp safe_enqueue(ring, message, options \\ []) do
    Outbox.enqueue(ring, message, options)
  rescue
    # The ring's table died with its owner between the route lookup and the
    # publish. The ring cannot count a drop it never reached, so it is counted
    # here, as the disconnect it is.
    ArgumentError ->
      record_closed_destination(message)
      {:dropped, :closed_destination}
  end

  defp record_closed_destination({:recv_packet, _source, packet}),
    do: record_closed_destination_packet(packet)

  defp record_closed_destination({:forward_packet, _source, _destination, packet}),
    do: record_closed_destination_packet(packet)

  defp record_closed_destination(_lifecycle_message), do: :ok

  defp record_closed_destination_packet(packet) do
    kind = if Disco.looks_like_wrapper?(packet), do: :disco, else: :other
    Metrics.add_drop(Metrics.default_handle(), :gone_disconnected, kind, byte_size(packet))
  end

  # The router is a singleton: waiting a millisecond for one connection's writer
  # is a millisecond every other connection waits for the router, so lifecycle
  # fan-out never naps on a held queue lock. It does not drop the frame either.
  # A presence change is state, and ADR 0003 promises a watcher's view is
  # complete or absent, so a frame that loses the lock is parked and retried in
  # order, and a watcher whose parked frames pass the soft cap is closed.
  defp notify_enqueue(ring, message, connection) do
    if parked?(connection) do
      park(connection, ring, message, :already_parked)
    else
      case safe_enqueue(ring, message, wait: false) do
        {:dropped, :contention} -> park(connection, ring, message, :newly_parked)
        result -> result
      end
    end
  end

  defp parked?(connection) do
    case :ets.next(@pending_table, {connection, -1}) do
      {^connection, _sequence} -> true
      _none -> false
    end
  end

  # The flush is already on its way for a connection that is already parked, so
  # only the frame that parks it asks for one: a backlog of a thousand frames
  # would otherwise put a thousand flush messages in the router's mailbox for a
  # backlog it is already draining.
  defp park(connection, ring, message, parked_state) do
    :ok = Metrics.add(Metrics.default_handle(), :lifecycle_contention, 1)
    sequence = :erlang.unique_integer([:positive, :monotonic])
    true = :ets.insert(@pending_table, {{connection, sequence}, ring, message})
    if parked_state == :newly_parked, do: send(self(), :derpex_flush_lifecycle)
    {:ok, :parked}
  end

  # One bounded pass per message, so flushing a backlog never holds the router.
  # A connection whose queue is still locked is skipped to the next connection
  # rather than ending the pass: the table is shared and ordered by pid, so
  # stopping at the first locked queue let one watcher's writer hold up the
  # presence frames of every watcher that sorts after it. Each connection's own
  # frames stay in order, because the skip is to the next connection.
  defp flush_parked(budget), do: flush_parked(:ets.first(@pending_table), budget, false)

  defp flush_parked(:"$end_of_table", _budget, contended?), do: end_flush(contended?)

  defp flush_parked(_key, 0, contended?), do: end_flush(contended?, :more_to_do)

  defp flush_parked({connection, _sequence} = key, budget, contended?) do
    [{^key, ring, message}] = :ets.lookup(@pending_table, key)

    case safe_enqueue(ring, message, wait: false) do
      {:dropped, :contention} ->
        flush_parked(
          :ets.next(@pending_table, {connection, :end_of_connection}),
          budget - 1,
          true
        )

      _delivered_or_closed ->
        true = :ets.delete(@pending_table, key)
        flush_parked(:ets.next(@pending_table, key), budget - 1, contended?)
    end
  end

  defp end_flush(contended?, remaining \\ :done)

  defp end_flush(true, _remaining) do
    _timer = Process.send_after(self(), :derpex_flush_lifecycle, @flush_retry_ms)
    :ok
  end

  defp end_flush(false, :more_to_do) do
    send(self(), :derpex_flush_lifecycle)
    :ok
  end

  defp end_flush(false, :done), do: :ok

  defp forget_parked(connection) do
    :ets.select_delete(@pending_table, [{{{connection, :_}, :_, :_}, [], [true]}])
  end

  defp route_forwarder(source, destination, packet) do
    case :ets.lookup(@forwarders_table, destination) do
      [{^destination, _identity, ring}] ->
        # Go's `handleFrameSendPacket` does `s.packetsForwardedOut.Add(1)`
        # before `fwd.ForwardPacket(...)` and ignores the error, so the counter
        # measures forwarding attempts. Counting only successes here would make
        # DERPEX's series disagree with the oracle's on every dropped forward.
        Metrics.add(Metrics.default_handle(), :packets_forwarded_out, 1)
        record_forwarded(safe_enqueue(ring, {:forward_packet, source, destination, packet}))

      [] ->
        {:dropped, :unknown_destination}
    end
  end

  # The kind/reason matrix already carries a forwarding drop under the packet's
  # own class. This counter is the one thing that matrix cannot say: that the
  # packet was on its way to another region.
  defp record_forwarded({:dropped, _reason} = result) do
    Metrics.add(Metrics.default_handle(), :packets_forwarded_dropped, 1)
    result
  end

  defp record_forwarded(result), do: result

  defp publish_preferred_forwarder(key, []) do
    true = :ets.delete(@forwarders_table, key)
  end

  defp publish_preferred_forwarder(key, entries) do
    {identity, ring, _sequence} = Enum.min_by(entries, &elem(&1, 2))
    true = :ets.insert(@forwarders_table, {key, identity, ring})
  end

  defp activity_sequence, do: :erlang.unique_integer([:positive, :monotonic])

  defp topology_stats(state) do
    registration_count =
      Enum.sum(Enum.map(state.routes, fn {_key, entries} -> length(entries) end))

    duplicate_entries =
      Enum.filter(state.routes, fn {_key, entries} -> length(entries) > 1 end)

    duplicate_connections =
      Enum.sum(Enum.map(duplicate_entries, fn {_key, entries} -> length(entries) end))

    not_ideal_connections =
      Enum.sum(
        Enum.map(state.routes, fn {_key, entries} ->
          Enum.count(entries, fn {_connection, _ordinary, _disco, _lifecycle, _activity, presence} ->
            Bitwise.band(presence.flags, 0x08) != 0
          end)
        end)
      )

    all_client_keys =
      state.routes
      |> Map.keys()
      |> MapSet.new()
      |> MapSet.union(MapSet.new(Map.keys(state.forwarders)))

    %{
      current_connections: registration_count,
      current_not_ideal_connections: not_ideal_connections,
      clients_total: MapSet.size(all_client_keys),
      clients_local: map_size(state.routes),
      clients_remote: MapSet.size(all_client_keys) - map_size(state.routes),
      current_duplicate_client_keys: length(duplicate_entries),
      current_duplicate_connections: duplicate_connections,
      watchers: map_size(state.watchers),
      forwarder_keys: map_size(state.forwarders),
      forwarder_paths:
        Enum.sum(Enum.map(state.forwarders, fn {_key, entries} -> length(entries) end))
    }
  end

  defp debug_client_keys(routes) do
    Enum.reduce(routes, %{}, fn {key, entries}, clients ->
      Enum.reduce(entries, clients, fn
        {_connection, _ordinary, _disco, _lifecycle, _activity, presence}, clients ->
          Map.put(clients, {decode_ip(presence.ip), presence.port}, key)
      end)
    end)
  end

  defp decode_ip(<<0::80, 0xFFFF::16, a, b, c, d>>), do: {a, b, c, d}

  defp decode_ip(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>),
    do: {a, b, c, d, e, f, g, h}

  defp check_consistency(state) do
    expected_routes = map_size(state.routes)

    expected_registrations =
      Enum.sum(Enum.map(state.routes, fn {_key, entries} -> length(entries) end))

    expected_duplicates = Enum.count(state.routes, fn {_key, entries} -> length(entries) > 1 end)

    errors =
      []
      |> check_size(@table, expected_routes, "active routes")
      |> check_size(@registrations_table, expected_registrations, "registrations")
      |> check_size(@duplicates_table, expected_duplicates, "duplicate keys")
      |> check_size(@forwarders_table, map_size(state.forwarders), "forwarder keys")
      |> check_active_routes(state.routes)

    case errors do
      [] -> :ok
      errors -> {:error, errors |> Enum.reverse() |> Enum.join(", ")}
    end
  end

  defp check_size(errors, table, expected, label) do
    actual = :ets.info(table, :size)

    if actual == expected,
      do: errors,
      else: ["#{label} table=#{actual} state=#{expected}" | errors]
  end

  defp check_active_routes(errors, routes) do
    Enum.reduce(routes, errors, &check_active_route/2)
  end

  defp check_active_route({key, entries}, errors) do
    case :ets.lookup(@table, key) do
      [{^key, connection, _ordinary, _disco, _lifecycle}] ->
        check_registered_connection(entries, connection, errors)

      [] ->
        ["serialized route is absent from active table" | errors]
    end
  end

  defp check_registered_connection(entries, connection, errors) do
    if registered_connection?(entries, connection),
      do: errors,
      else: ["active route is absent from registrations" | errors]
  end

  defp registered_connection?(entries, connection) do
    Enum.any?(entries, fn
      {^connection, _ordinary, _disco, _lifecycle, _activity, _presence} -> true
      _different -> false
    end)
  end
end
