defmodule Derpex.AcceptLimiter do
  @moduledoc """
  Bounded global and per-source admission before per-connection DERP allocation.

  Per-IP token buckets are retained in a fixed-size least-recently-used set.
  Concurrent connection claims are monitored so abrupt handler exits cannot
  leak capacity.

  The tracking set is a memory bound, not an admission bound. When every
  tracked IP holds a live connection there is nothing to evict, so a new source
  is admitted *untracked*: it consumes the shared accept token but no per-IP
  bucket, no per-IP connection slot, and no monitor. Each such admission
  increments `:ip_untracked`, so the loss of per-IP enforcement is visible in
  the operational counters rather than turning into a self-inflicted outage.
  """

  use GenServer

  alias Derpex.Clock
  alias Derpex.RateLimiter

  @default_max_tracked_ips 16_384

  @type rate_config :: {number(), pos_integer()}
  @type config :: nil | rate_config() | keyword()

  @doc false
  def start_link(options \\ []) do
    case Keyword.fetch(options, :name) do
      {:ok, nil} -> GenServer.start_link(__MODULE__, options)
      {:ok, name} -> GenServer.start_link(__MODULE__, options, name: name)
      :error -> GenServer.start_link(__MODULE__, options, name: __MODULE__)
    end
  end

  @doc "Consumes one shared accept token, or allows immediately when disabled."
  @spec allow?(GenServer.server() | nil) :: boolean()
  def allow?(server \\ __MODULE__)

  def allow?(nil), do: true
  def allow?(server), do: GenServer.call(server, :allow)

  @doc "Claims one pre-authentication connection slot for the calling process."
  @spec claim(GenServer.server() | nil, :inet.ip_address()) ::
          :ok
          | {:error, :accept_rate_limited | :ip_rate_limited | :ip_connection_limited}
  def claim(server \\ __MODULE__, source_ip)

  def claim(nil, _source_ip), do: :ok
  def claim(server, source_ip), do: GenServer.call(server, {:claim, source_ip})

  @doc "Releases the calling process's connection claim. Idempotent."
  @spec release(GenServer.server() | nil) :: :ok
  def release(server \\ __MODULE__)

  def release(nil), do: :ok

  def release(server) do
    GenServer.call(server, :release)
  catch
    :exit, _reason -> :ok
  end

  @doc "Replaces the limiter live; existing connections no longer consume slots."
  @spec update(GenServer.server(), config()) :: :ok
  def update(server, config), do: GenServer.call(server, {:update, config})

  @spec update(config()) :: :ok
  def update(config), do: update(__MODULE__, config)

  @doc "Returns bounded operational counters without source-IP labels."
  @spec stats(GenServer.server()) :: map()
  def stats(server \\ __MODULE__), do: GenServer.call(server, :stats)

  @impl true
  def init(options) do
    {:ok, new_state(Keyword.get(options, :config))}
  end

  @impl true
  def handle_call(:allow, _from, state) do
    {allowed?, global} = allow_bucket(state.global)

    state =
      state
      |> Map.put(:global, global)
      |> count(if(allowed?, do: :allowed, else: :accept_rate_limited))

    {:reply, allowed?, state}
  end

  def handle_call({:claim, source_ip}, {pid, _tag}, state) do
    cond do
      Map.has_key?(state.claims, pid) ->
        {:reply, :ok, state}

      not valid_ip?(source_ip) ->
        {:reply, {:error, :ip_connection_limited}, count(state, :ip_connection_limited)}

      true ->
        {reply, state} = claim_connection(state, source_ip, pid)
        {:reply, reply, state}
    end
  end

  def handle_call(:release, {pid, _tag}, state) do
    {:reply, :ok, release_claim(state, pid, true)}
  end

  def handle_call({:update, config}, _from, state) do
    state = demonitor_claims(state)
    {:reply, :ok, %{new_state(config) | counters: state.counters}}
  end

  def handle_call(:stats, _from, state) do
    reply =
      state.counters
      |> Map.put(:tracked_ips, map_size(state.entries))
      |> Map.put(:active_connections, map_size(state.claims))
      |> Map.put(:max_tracked_ips, state.max_tracked_ips)

    {:reply, reply, state}
  end

  @impl true
  def handle_info({:DOWN, reference, :process, pid, _reason}, state) do
    case state.claims[pid] do
      %{monitor: ^reference} -> {:noreply, release_claim(state, pid, false)}
      _stale -> {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp claim_connection(state, source_ip, pid) do
    now = Clock.monotonic_time(:millisecond)
    {global_allowed?, global} = allow_bucket(state.global, now)
    state = %{state | global: global}

    with true <- global_allowed? || {:error, :accept_rate_limited},
         {:ok, entry, state} <- fetch_entry(state, source_ip),
         {true, entry} <- allow_entry_bucket(entry, now) do
      if connection_available?(entry, state.per_ip_connections) do
        {entry, state} = touch_entry(state, source_ip, entry, now)
        state = maybe_monitor_claim(state, source_ip, pid, entry)
        {:ok, count(state, :allowed)}
      else
        state = put_touched_entry(state, source_ip, entry, now)
        {{:error, :ip_connection_limited}, count(state, :ip_connection_limited)}
      end
    else
      {:error, reason} ->
        {{:error, reason}, count(state, reason)}

      {false, entry} ->
        state = put_touched_entry(state, source_ip, entry, now)
        {{:error, :ip_rate_limited}, count(state, :ip_rate_limited)}
    end
  end

  defp fetch_entry(%{per_ip: nil, per_ip_connections: nil} = state, _source_ip),
    do: {:ok, nil, state}

  defp fetch_entry(state, source_ip) do
    case Map.fetch(state.entries, source_ip) do
      {:ok, entry} ->
        {:ok, entry, remove_evictable(state, entry)}

      :error ->
        case ensure_tracking_capacity(state) do
          {:ok, state} ->
            entry = %{bucket: new_bucket(state.per_ip), connections: 0, lru_key: nil}
            {:ok, entry, state}

          {:untracked, state} ->
            {:ok, nil, count(state, :ip_untracked)}
        end
    end
  end

  defp ensure_tracking_capacity(state) when map_size(state.entries) < state.max_tracked_ips,
    do: {:ok, state}

  defp ensure_tracking_capacity(%{evictable: evictable} = state) do
    if :gb_trees.is_empty(evictable) do
      {:untracked, state}
    else
      {_lru_key, source_ip, evictable} = :gb_trees.take_smallest(evictable)
      {:ok, %{state | entries: Map.delete(state.entries, source_ip), evictable: evictable}}
    end
  end

  defp allow_entry_bucket(nil, _now), do: {true, nil}

  defp allow_entry_bucket(entry, now) do
    {allowed?, bucket} = allow_bucket(entry.bucket, now)
    {allowed?, %{entry | bucket: bucket}}
  end

  defp connection_available?(nil, _maximum), do: true
  defp connection_available?(_entry, nil), do: true
  defp connection_available?(entry, maximum), do: entry.connections < maximum

  defp touch_entry(state, _source_ip, nil, _now), do: {nil, state}

  defp touch_entry(state, source_ip, entry, now) do
    entry = %{entry | lru_key: {now, state.sequence}}

    {entry,
     %{
       state
       | entries: Map.put(state.entries, source_ip, entry),
         sequence: state.sequence + 1
     }}
  end

  defp put_touched_entry(state, source_ip, entry, now) do
    {entry, state} = touch_entry(state, source_ip, entry, now)
    add_evictable(state, source_ip, entry)
  end

  defp maybe_monitor_claim(state, _source_ip, _pid, nil), do: state

  defp maybe_monitor_claim(%{per_ip_connections: nil} = state, source_ip, _pid, entry) do
    add_evictable(state, source_ip, entry)
  end

  defp maybe_monitor_claim(state, source_ip, pid, entry) do
    reference = Process.monitor(pid)
    entry = %{entry | connections: entry.connections + 1, lru_key: nil}

    %{
      state
      | entries: Map.put(state.entries, source_ip, entry),
        claims: Map.put(state.claims, pid, %{source_ip: source_ip, monitor: reference})
    }
  end

  defp release_claim(state, pid, demonitor?) do
    case Map.pop(state.claims, pid) do
      {nil, _claims} ->
        state

      {%{source_ip: source_ip, monitor: reference}, claims} ->
        if demonitor?, do: Process.demonitor(reference, [:flush])
        entry = Map.fetch!(state.entries, source_ip)
        entry = %{entry | connections: max(entry.connections - 1, 0)}
        state = %{state | claims: claims, entries: Map.put(state.entries, source_ip, entry)}

        if entry.connections == 0 do
          put_touched_entry(state, source_ip, entry, Clock.monotonic_time(:millisecond))
        else
          state
        end
    end
  end

  defp add_evictable(state, _source_ip, nil), do: state

  defp add_evictable(state, source_ip, %{connections: 0, lru_key: lru_key}) do
    %{state | evictable: :gb_trees.enter(lru_key, source_ip, state.evictable)}
  end

  defp add_evictable(state, _source_ip, _entry), do: state

  defp remove_evictable(state, %{connections: 0, lru_key: lru_key}) when not is_nil(lru_key) do
    %{state | evictable: :gb_trees.delete_any(lru_key, state.evictable)}
  end

  defp remove_evictable(state, _entry), do: state

  defp demonitor_claims(state) do
    Enum.each(state.claims, fn {_pid, %{monitor: monitor}} ->
      Process.demonitor(monitor, [:flush])
    end)

    state
  end

  defp allow_bucket(nil, _now), do: {true, nil}
  defp allow_bucket(bucket, now), do: RateLimiter.allow(bucket, now)
  defp allow_bucket(bucket), do: allow_bucket(bucket, Clock.monotonic_time(:millisecond))

  defp new_state(config) do
    {global, per_ip, per_ip_connections, max_tracked_ips} = parse_config!(config)

    %{
      global: new_bucket(global),
      per_ip: per_ip,
      per_ip_connections: per_ip_connections,
      max_tracked_ips: max_tracked_ips,
      entries: %{},
      evictable: :gb_trees.empty(),
      sequence: 0,
      claims: %{},
      counters: %{
        allowed: 0,
        accept_rate_limited: 0,
        ip_rate_limited: 0,
        ip_connection_limited: 0,
        ip_tracking_limited: 0,
        ip_untracked: 0
      }
    }
  end

  defp parse_config!(nil), do: {nil, nil, nil, @default_max_tracked_ips}

  defp parse_config!({rate, burst}),
    do: {validate_rate!({rate, burst}), nil, nil, @default_max_tracked_ips}

  defp parse_config!(config) when is_list(config) do
    global = config |> Keyword.get(:global) |> validate_optional_rate!()
    per_ip = config |> Keyword.get(:per_ip) |> validate_optional_rate!()

    per_ip_connections =
      positive_or_nil!(Keyword.get(config, :per_ip_connections), :per_ip_connections)

    max_tracked_ips =
      positive!(Keyword.get(config, :max_tracked_ips, @default_max_tracked_ips), :max_tracked_ips)

    {global, per_ip, per_ip_connections, max_tracked_ips}
  end

  defp parse_config!(_invalid), do: raise(ArgumentError, "invalid accept limiter configuration")

  defp validate_optional_rate!(nil), do: nil
  defp validate_optional_rate!(config), do: validate_rate!(config)

  defp validate_rate!({rate, burst})
       when is_number(rate) and rate >= 0 and is_integer(burst) and burst > 0,
       do: {rate, burst}

  defp validate_rate!(_invalid),
    do: raise(ArgumentError, "rate must be a non-negative number with a positive burst")

  defp positive_or_nil!(nil, _name), do: nil
  defp positive_or_nil!(value, name), do: positive!(value, name)

  defp positive!(value, _name) when is_integer(value) and value > 0, do: value
  defp positive!(_value, name), do: raise(ArgumentError, "#{name} must be a positive integer")

  defp new_bucket(nil), do: nil
  defp new_bucket({rate, burst}), do: RateLimiter.new(rate, burst)

  defp count(state, key), do: update_in(state.counters[key], &(&1 + 1))

  defp valid_ip?({a, b, c, d}) do
    values = [a, b, c, d]
    Enum.all?(values, &is_integer/1) and Enum.all?(values, &(&1 in 0..255))
  end

  defp valid_ip?({a, b, c, d, e, f, g, h}) do
    values = [a, b, c, d, e, f, g, h]
    Enum.all?(values, &is_integer/1) and Enum.all?(values, &(&1 in 0..65_535))
  end

  defp valid_ip?(_invalid), do: false
end
