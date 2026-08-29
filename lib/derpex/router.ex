defmodule Derpex.Router do
  @moduledoc """
  Serializes connection topology while keeping successful packet routing in ETS.

  `route/3` never calls this GenServer. It performs one protected-table lookup
  and publishes directly into the destination's bounded ring.
  """

  use GenServer

  alias Derpex.Disco
  alias Derpex.Metrics
  alias Derpex.Outbox.Ring

  @table __MODULE__.Routes
  @reverse_table __MODULE__.ReversePaths
  @registrations_table __MODULE__.Registrations
  @duplicates_table __MODULE__.Duplicates
  @forwarders_table __MODULE__.Forwarders

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
        %Ring{} = lifecycle
      )
      when is_pid(connection) do
    register(key, connection, ordinary, ordinary, lifecycle)
  end

  @doc "Makes a connection active with separate ordinary, disco, and lifecycle rings."
  @spec register(binary(), pid(), Ring.t(), Ring.t(), Ring.t()) :: :ok
  def register(
        <<key::binary-size(32)>>,
        connection,
        %Ring{} = ordinary,
        %Ring{} = disco,
        %Ring{} = lifecycle
      )
      when is_pid(connection) do
    register(key, connection, ordinary, disco, lifecycle, @default_presence)
  end

  @doc "Makes a connection active and publishes its watcher-presence metadata."
  @spec register(binary(), pid(), Ring.t(), Ring.t(), Ring.t(), presence()) :: :ok
  def register(
        <<key::binary-size(32)>>,
        connection,
        %Ring{} = ordinary,
        %Ring{} = disco,
        %Ring{} = lifecycle,
        %{
          ip: <<_ip::binary-size(16)>>,
          port: port,
          flags: flags,
          app_name: app_name
        } = presence
      )
      when is_pid(connection) and port in 0..65_535 and flags in 0..255 and
             is_binary(app_name) do
    GenServer.call(
      __MODULE__,
      {:register, key, connection, ordinary, disco, lifecycle, presence}
    )
  end

  @doc "Removes a connection only if it is still the active route."
  @spec unregister(binary(), pid()) :: :ok
  def unregister(<<key::binary-size(32)>>, connection) when is_pid(connection) do
    GenServer.call(__MODULE__, {:unregister, key, connection})
  end

  @doc "Subscribes a trusted connection to the current snapshot and future presence changes."
  @spec watch(pid(), Ring.t()) :: :ok
  def watch(connection, %Ring{} = lifecycle) when is_pid(connection) do
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
  def note_send(<<source::binary-size(32)>>, destination_connection, %Ring{} = lifecycle)
      when is_pid(destination_connection) do
    true = :ets.insert(@reverse_table, {{source, destination_connection}, lifecycle})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc "Promotes a duplicate connection when it is the latest one to send a frame."
  @spec note_activity(binary(), pid()) :: :ok
  def note_activity(<<key::binary-size(32)>>, connection) when is_pid(connection) do
    with [{^key}] <- :ets.lookup(@duplicates_table, key),
         [{{^key, ^connection}, ordinary, {disco, lifecycle}, activity}] <-
           :ets.lookup(@registrations_table, {key, connection}) do
      :atomics.put(activity, 1, activity_sequence())
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

    reverse_table =
      :ets.new(@reverse_table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
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
       reverse_table: reverse_table,
       registrations_table: registrations_table,
       duplicates_table: duplicates_table,
       forwarders_table: forwarders_table,
       watchers: %{},
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
    activity = :atomics.new(1, signed: false)
    :atomics.put(activity, 1, activity_sequence())

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

    {:reply, :ok, %{state | monitors: monitors, routes: Map.put(state.routes, key, entries)}}
  end

  def handle_call({:unregister, key, connection}, _from, state) do
    had_key? = Map.has_key?(state.routes, key)
    routes = remove_route(state.routes, key, connection)
    monitors = remove_connection_key(state.monitors, connection, key)

    if had_key? and not Map.has_key?(routes, key) do
      broadcast(state.watchers, {:peer_gone, key, 0x00})
    end

    forget_destination(connection)
    watchers = Map.delete(state.watchers, connection)
    {:reply, :ok, %{state | monitors: monitors, routes: routes, watchers: watchers}}
  end

  def handle_call({:watch, connection, lifecycle}, _from, state) do
    state.routes
    |> snapshot_presence()
    |> Enum.each(fn message ->
      _enqueue_result = safe_enqueue(lifecycle, message)
    end)

    {monitor, monitors} = ensure_monitor(state.monitors, connection)
    monitors = Map.put(monitors, connection, {monitor, keys_for(monitors, connection)})

    {:reply, :ok,
     %{
       state
       | monitors: monitors,
         watchers: Map.put(state.watchers, connection, lifecycle)
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
    registered? =
      state.forwarders
      |> Map.get(key, [])
      |> Enum.any?(fn {registered_identity, _ring, _sequence} ->
        registered_identity == identity
      end)

    entries =
      state.forwarders
      |> Map.get(key, [])
      |> Enum.reject(fn {registered_identity, _ring, _sequence} ->
        registered_identity == identity
      end)

    publish_preferred_forwarder(key, entries)

    forwarders =
      if entries == [] do
        Map.delete(state.forwarders, key)
      else
        Map.put(state.forwarders, key, entries)
      end

    forwarder_monitors =
      if registered? do
        remove_forwarder_monitor(state.forwarder_monitors, identity, key)
      else
        state.forwarder_monitors
      end

    {:reply, :ok, %{state | forwarders: forwarders, forwarder_monitors: forwarder_monitors}}
  end

  def handle_call({:forwarder_count, key}, _from, state) do
    {:reply, state.forwarders |> Map.get(key, []) |> length(), state}
  end

  @impl true
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
        {routes, gone_keys} = remove_connection_routes(state.routes, keys, connection)

        Enum.each(gone_keys, &broadcast(state.watchers, {:peer_gone, &1, 0x00}))
        forget_destination(connection)

        %{
          state
          | monitors: Map.delete(state.monitors, connection),
            routes: routes,
            watchers: Map.delete(state.watchers, connection)
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
            remove_dead_forwarder(forwarders, key, identity)
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

  defp remove_dead_forwarder(forwarders, key, identity) do
    entries =
      forwarders
      |> Map.get(key, [])
      |> Enum.reject(fn {registered_identity, _ring, _sequence} ->
        registered_identity == identity
      end)

    publish_preferred_forwarder(key, entries)

    if entries == [] do
      Map.delete(forwarders, key)
    else
      Map.put(forwarders, key, entries)
    end
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

  defp remove_connection_routes(routes, keys, connection) do
    Enum.reduce(keys, {routes, []}, fn key, {routes, gone_keys} ->
      had_key? = Map.has_key?(routes, key)
      routes = remove_route(routes, key, connection)

      if had_key? and not Map.has_key?(routes, key) do
        {routes, [key | gone_keys]}
      else
        {routes, gone_keys}
      end
    end)
  end

  defp remove_route(routes, key, connection) do
    true = :ets.delete(@registrations_table, {key, connection})

    entries =
      routes
      |> Map.get(key, [])
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

    update_duplicate_marker(key, entries)

    case entries do
      [] ->
        true = :ets.delete(@table, key)
        notify_peer_gone(key)
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

  defp notify_peer_gone(key) do
    @reverse_table
    |> :ets.match_object({{key, :_}, :_})
    |> Enum.each(fn {{^key, _destination_connection}, lifecycle} = entry ->
      true = :ets.delete_object(@reverse_table, entry)
      _enqueue_result = safe_enqueue(lifecycle, {:peer_gone, key, 0x00})
    end)
  end

  defp forget_destination(connection) do
    true = :ets.match_delete(@reverse_table, {{:_, connection}, :_})
    :ok
  end

  defp update_duplicate_marker(key, entries) do
    if length(entries) > 1 do
      true = :ets.insert(@duplicates_table, {key})
    else
      true = :ets.delete(@duplicates_table, key)
    end
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
    Enum.each(watchers, fn {_connection, lifecycle} ->
      _enqueue_result = safe_enqueue(lifecycle, message)
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

  defp safe_enqueue(ring, message) do
    Ring.enqueue(ring, message)
  rescue
    ArgumentError -> {:dropped, :closed_destination}
  end

  defp route_forwarder(source, destination, packet) do
    case :ets.lookup(@forwarders_table, destination) do
      [{^destination, _identity, ring}] ->
        result = safe_enqueue(ring, {:forward_packet, source, destination, packet})

        case result do
          {:ok, _enqueue_result} ->
            Metrics.add(Metrics.default_handle(), :packets_forwarded_out, 1)

          {:dropped, _reason} ->
            :ok
        end

        result

      [] ->
        {:dropped, :unknown_destination}
    end
  end

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
