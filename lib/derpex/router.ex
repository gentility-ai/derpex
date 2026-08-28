defmodule Derpex.Router do
  @moduledoc """
  Serializes connection topology while keeping successful packet routing in ETS.

  `route/3` never calls this GenServer. It performs one protected-table lookup
  and publishes directly into the destination's bounded ring.
  """

  use GenServer

  alias Derpex.Disco
  alias Derpex.Outbox.Ring

  @table __MODULE__.Routes
  @reverse_table __MODULE__.ReversePaths
  @registrations_table __MODULE__.Registrations
  @duplicates_table __MODULE__.Duplicates

  @type route_result :: Ring.enqueue_result() | {:dropped, :unknown_destination}

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
    GenServer.call(__MODULE__, {:register, key, connection, ordinary, disco, lifecycle})
  end

  @doc "Removes a connection only if it is still the active route."
  @spec unregister(binary(), pid()) :: :ok
  def unregister(<<key::binary-size(32)>>, connection) when is_pid(connection) do
    GenServer.call(__MODULE__, {:unregister, key, connection})
  end

  @doc "Publishes a packet directly to the active destination ring."
  @spec route(binary(), binary(), binary()) :: route_result()
  def route(<<source::binary-size(32)>>, <<destination::binary-size(32)>>, packet)
      when is_binary(packet) do
    case :ets.lookup(@table, destination) do
      [{^destination, _connection, ordinary, disco, _lifecycle}] ->
        ring = if Disco.looks_like_wrapper?(packet), do: disco, else: ordinary
        Ring.enqueue(ring, {:recv_packet, source, packet})

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

    {:ok,
     %{
       table: table,
       reverse_table: reverse_table,
       registrations_table: registrations_table,
       duplicates_table: duplicates_table,
       monitors: %{},
       routes: %{}
     }}
  end

  @impl true
  def handle_call(
        {:register, key, connection, ordinary, disco, lifecycle},
        _from,
        state
      ) do
    {monitor, monitors} = ensure_monitor(state.monitors, connection)
    activity = :atomics.new(1, signed: false)
    :atomics.put(activity, 1, activity_sequence())

    entries =
      state.routes
      |> Map.get(key, [])
      |> Enum.reject(fn {registered_connection, _ordinary, _disco, _lifecycle, _activity} ->
        registered_connection == connection
      end)
      |> Kernel.++([{connection, ordinary, disco, lifecycle, activity}])

    true =
      :ets.insert(
        @registrations_table,
        {{key, connection}, ordinary, {disco, lifecycle}, activity}
      )

    update_duplicate_marker(key, entries)
    true = :ets.insert(@table, {key, connection, ordinary, disco, lifecycle})

    monitors =
      Map.put(monitors, connection, {monitor, MapSet.put(keys_for(monitors, connection), key)})

    {:reply, :ok, %{state | monitors: monitors, routes: Map.put(state.routes, key, entries)}}
  end

  def handle_call({:unregister, key, connection}, _from, state) do
    routes = remove_route(state.routes, key, connection)
    monitors = remove_connection_key(state.monitors, connection, key)
    forget_destination(connection)
    {:reply, :ok, %{state | monitors: monitors, routes: routes}}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, connection, _reason}, state) do
    case Map.pop(state.monitors, connection) do
      {{^monitor, keys}, monitors} ->
        routes =
          Enum.reduce(keys, state.routes, fn key, routes ->
            remove_route(routes, key, connection)
          end)

        forget_destination(connection)
        {:noreply, %{state | monitors: monitors, routes: routes}}

      {nil, _monitors} ->
        {:noreply, state}
    end
  end

  defp ensure_monitor(monitors, connection) do
    case monitors[connection] do
      {monitor, _keys} -> {monitor, monitors}
      nil -> {Process.monitor(connection), monitors}
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

  defp remove_route(routes, key, connection) do
    true = :ets.delete(@registrations_table, {key, connection})

    entries =
      routes
      |> Map.get(key, [])
      |> Enum.reject(fn {registered_connection, _ordinary, _disco, _lifecycle, _activity} ->
        registered_connection == connection
      end)

    update_duplicate_marker(key, entries)

    case entries do
      [] ->
        true = :ets.delete(@table, key)
        notify_peer_gone(key)
        Map.delete(routes, key)

      _remaining ->
        {active_connection, active_ordinary, active_disco, active_lifecycle, _activity} =
          Enum.max_by(entries, fn {_connection, _ordinary, _disco, _lifecycle, activity} ->
            :atomics.get(activity, 1)
          end)

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
      _enqueue_result = Ring.enqueue(lifecycle, {:peer_gone, key, 0x00})
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

  defp activity_sequence, do: :erlang.unique_integer([:positive, :monotonic])
end
