defmodule Derpex.Admission.Gentility do
  @moduledoc """
  Bounded Gentility admission leases, outage reconnects, and active revocation.

  Live authorization is attempted outside the controller process so expiry and
  revocation remain responsive during a control-plane outage. An atomic gate
  rejects excess work before it can enter the controller mailbox.
  """

  use GenServer

  @behaviour Derpex.Admission

  alias Derpex.Admission.Gentility.Cache
  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Request
  alias Derpex.Clock
  alias Derpex.Router

  @default_max_cache_entries 10_000
  @default_max_revocations 10_000
  @default_max_concurrent_requests 64
  @default_authority_timeout 2_000
  @default_max_lease_ms 15 * 60 * 1_000
  @default_max_future_skew_ms 30_000

  defmodule Policy do
    @moduledoc "An immutable, lock-free admission handle obtained from a running controller."

    @enforce_keys [:server, :authority, :gate, :max_concurrent_requests, :authority_timeout]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            server: GenServer.server(),
            authority: term(),
            gate: :atomics.atomics_ref(),
            max_concurrent_requests: pos_integer(),
            authority_timeout: pos_integer()
          }
  end

  @type authority ::
          module() | {module(), term()} | (Request.t() -> {:ok, binary()} | {:error, term()})

  @doc "Starts a lease controller."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options) do
    {name, options} = Keyword.pop(options, :name)
    options = Keyword.put(options, :server, name)
    GenServer.start_link(__MODULE__, options, if(name, do: [name: name], else: []))
  end

  @doc "Returns the bounded policy handle to install in a DERP listener."
  @spec policy(GenServer.server()) :: Policy.t()
  def policy(server), do: GenServer.call(server, :policy)

  @impl Derpex.Admission
  def authorize(%Request{} = request, %Policy{} = policy) do
    with :ok <- reserve(policy.gate, policy.max_concurrent_requests) do
      try do
        authorize_reserved(request, policy)
      after
        :atomics.sub(policy.gate, 1, 1)
      end
    end
  end

  def authorize(%Request{} = request, server) do
    authorize(request, policy(server))
  catch
    :exit, _reason -> {:error, :admission_unavailable}
  end

  @doc "Applies an authenticated revocation and closes all affected local duplicates."
  @spec revoke(GenServer.server(), binary()) :: {:ok, :applied | :stale} | {:error, term()}
  def revoke(server, signed_revocation) when is_binary(signed_revocation) do
    GenServer.call(server, {:revoke, signed_revocation})
  end

  @doc "Applies a reconciliation batch of signed revocations in one durable update."
  @spec reconcile(GenServer.server(), [binary()]) ::
          {:ok, %{applied: non_neg_integer(), stale: non_neg_integer()}} | {:error, term()}
  def reconcile(server, signed_revocations) when is_list(signed_revocations) do
    GenServer.call(server, {:reconcile, signed_revocations})
  end

  @doc "Replaces the bounded verification keyring and invalidates records it can no longer verify."
  @spec update_verification_keys(GenServer.server(), map()) :: :ok | {:error, term()}
  def update_verification_keys(server, keys) when is_map(keys) do
    GenServer.call(server, {:update_verification_keys, keys})
  end

  @doc "Returns bounded controller state suitable for health checks and assertions."
  @spec stats(GenServer.server()) :: map()
  def stats(server), do: GenServer.call(server, :stats)

  @impl GenServer
  def init(options) do
    with {:ok, state} <- initial_state(options) do
      {:ok, state |> load_cache() |> purge_expired() |> reschedule_expiry()}
    end
  end

  @impl GenServer
  def handle_call(:policy, _from, state), do: {:reply, state.policy, state}

  def handle_call(:stats, _from, state) do
    reply = %{
      cache_entries: map_size(state.leases),
      revocations: map_size(state.revocations),
      active_requests: :atomics.get(state.policy.gate, 1),
      max_cache_entries: state.max_cache_entries,
      max_revocations: state.max_revocations,
      load_error: state.load_error,
      persist_error: state.persist_error
    }

    {:reply, reply, state}
  end

  def handle_call({:accept_live, node_key, wire}, _from, state) do
    state = purge_expired(state)

    case verify_lease(state, wire) do
      {:ok, %Lease{node_key: ^node_key} = lease} ->
        accept_verified_lease(state, wire, lease)

      {:ok, %Lease{}} ->
        {:reply, {:error, :lease_node_key_mismatch}, state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  def handle_call({:cached, node_key}, _from, state) do
    state = purge_expired(state)

    case state.leases[node_key] do
      nil ->
        {:reply, {:error, :no_cached_lease}, reschedule_expiry(state)}

      entry ->
        sequence = state.sequence + 1
        entry = %{entry | accessed: sequence}
        state = %{state | leases: Map.put(state.leases, node_key, entry), sequence: sequence}
        {:reply, {:ok, context(entry.lease, :cached)}, reschedule_expiry(state)}
    end
  end

  def handle_call({:revoke, wire}, _from, state) do
    case Contract.verify_revocation(wire, state.verification_keys) do
      {:ok, revocation} -> apply_one_revocation(state, wire, revocation)
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:reconcile, wires}, _from, state) do
    case verify_revocations(wires, state.verification_keys, state.max_revocations) do
      {:ok, revocations} -> apply_reconciliation(state, revocations)
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:update_verification_keys, keys}, _from, state) do
    case validate_verification_keys(keys) do
      :ok ->
        state = reverify_records(%{state | verification_keys: keys})
        state = persist_or_note_error(state)
        {:reply, :ok, state |> purge_expired() |> reschedule_expiry()}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_info({__MODULE__, :expire, token}, %{expiry_token: token} = state) do
    state = %{state | expiry_timer: nil, expiry_token: nil}
    {:noreply, state |> purge_expired() |> reschedule_expiry()}
  end

  def handle_info({__MODULE__, :expire, _stale}, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, state) do
    cancel_expiry(state)
    :ok
  end

  defp initial_state(options) do
    authority = Keyword.fetch!(options, :authority)
    server = Keyword.get(options, :server) || self()
    gate = :atomics.new(1, signed: false)

    max_concurrent_requests =
      positive_option!(options, :max_concurrent_requests, @default_max_concurrent_requests)

    authority_timeout = positive_option!(options, :authority_timeout, @default_authority_timeout)
    max_cache_entries = positive_option!(options, :max_cache_entries, @default_max_cache_entries)
    max_revocations = positive_option!(options, :max_revocations, @default_max_revocations)
    max_lease_ms = positive_option!(options, :max_lease_ms, @default_max_lease_ms)

    max_future_skew_ms =
      non_negative_option!(options, :max_future_skew_ms, @default_max_future_skew_ms)

    verification_keys = Keyword.fetch!(options, :verification_keys)

    with :ok <- validate_verification_keys(verification_keys) do
      policy = %Policy{
        server: server,
        authority: authority,
        gate: gate,
        max_concurrent_requests: max_concurrent_requests,
        authority_timeout: authority_timeout
      }

      {:ok,
       %{
         policy: policy,
         verification_keys: verification_keys,
         cache_path: Keyword.get(options, :cache_path),
         max_cache_entries: max_cache_entries,
         max_revocations: max_revocations,
         max_lease_ms: max_lease_ms,
         max_future_skew_ms: max_future_skew_ms,
         clock: Keyword.get(options, :clock, Clock),
         close_peer: Keyword.get(options, :close_peer, &Router.close_peer/1),
         leases: %{},
         revocations: %{},
         sequence: 0,
         expiry_timer: nil,
         expiry_token: nil,
         load_error: nil,
         persist_error: nil
       }}
    end
  end

  defp authorize_reserved(request, policy) do
    case invoke_with_timeout(policy.authority, request, policy.authority_timeout) do
      {:ok, {:ok, wire}} when is_binary(wire) ->
        controller_call(policy.server, {:accept_live, request.node_key, wire})

      {:ok, {:error, :unavailable}} ->
        controller_call(policy.server, {:cached, request.node_key})

      {:ok, {:error, reason}} ->
        {:error, reason}

      {:ok, other} ->
        {:error, {:invalid_authority_response, other}}

      {:error, _unavailable} ->
        controller_call(policy.server, {:cached, request.node_key})
    end
  end

  defp invoke_with_timeout(authority, request, timeout) do
    parent = self()
    reply_ref = make_ref()

    {pid, monitor} =
      spawn_monitor(fn -> send(parent, {reply_ref, invoke_authority(authority, request)}) end)

    receive do
      {^reply_ref, result} ->
        Process.demonitor(monitor, [:flush])
        {:ok, result}

      {:DOWN, ^monitor, :process, ^pid, reason} ->
        {:error, {:authority_exit, reason}}
    after
      timeout ->
        Process.exit(pid, :kill)
        receive do: ({:DOWN, ^monitor, :process, ^pid, _reason} -> :ok)
        {:error, :authority_timeout}
    end
  end

  defp invoke_authority(authority, request) when is_function(authority, 1),
    do: authority.(request)

  defp invoke_authority({module, options}, request) when is_atom(module),
    do: module.authorize(request, options)

  defp invoke_authority(module, request) when is_atom(module), do: module.authorize(request, [])

  defp controller_call(server, message) do
    GenServer.call(server, message)
  catch
    :exit, _reason -> {:error, :admission_unavailable}
  end

  defp reserve(gate, maximum) do
    current = :atomics.get(gate, 1)

    cond do
      current >= maximum ->
        {:error, :admission_overloaded}

      :atomics.compare_exchange(gate, 1, current, current + 1) == :ok ->
        :ok

      true ->
        reserve(gate, maximum)
    end
  end

  defp accept_verified_lease(state, wire, lease) do
    revoked_revision =
      state.revocations |> Map.get(lease.node_key, %{}) |> Map.get(:policy_revision, -1)

    if lease.policy_revision <= revoked_revision do
      {:reply, {:error, :lease_revoked}, state}
    else
      sequence = state.sequence + 1
      entry = %{wire: wire, lease: lease, accessed: sequence}

      {leases, evicted} =
        put_bounded(state.leases, lease.node_key, entry, state.max_cache_entries)

      revocations = Map.delete(state.revocations, lease.node_key)
      candidate = %{state | leases: leases, revocations: revocations, sequence: sequence}

      case persist(candidate) do
        :ok ->
          close_evicted(state, evicted)
          state = %{candidate | persist_error: nil} |> reschedule_expiry()
          {:reply, {:ok, context(lease, :live)}, state}

        {:error, reason} ->
          {:reply, {:error, {:cache_persist, reason}}, %{state | persist_error: reason}}
      end
    end
  end

  defp apply_one_revocation(state, wire, revocation) do
    case state.revocations[revocation.node_key] do
      %{policy_revision: revision} when revision >= revocation.policy_revision ->
        {:reply, {:ok, :stale}, state}

      _older_or_missing ->
        {state, close?} = put_revocation(state, wire, revocation)
        if close?, do: close_peer(state, revocation.node_key)
        state = persist_or_note_error(state) |> reschedule_expiry()
        {:reply, {:ok, :applied}, state}
    end
  end

  defp apply_reconciliation(state, revocations) do
    {state, applied, stale, close_keys} =
      Enum.reduce(revocations, {state, 0, 0, MapSet.new()}, &reconcile_revocation/2)

    Enum.each(close_keys, &close_peer(state, &1))
    state = persist_or_note_error(state) |> reschedule_expiry()
    {:reply, {:ok, %{applied: applied, stale: stale}}, state}
  end

  defp reconcile_revocation({wire, revocation}, {state, applied, stale, close_keys}) do
    case state.revocations[revocation.node_key] do
      %{policy_revision: revision} when revision >= revocation.policy_revision ->
        {state, applied, stale + 1, close_keys}

      _older_or_missing ->
        {state, close?} = put_revocation(state, wire, revocation)
        close_keys = maybe_put_close_key(close_keys, revocation.node_key, close?)
        {state, applied + 1, stale, close_keys}
    end
  end

  defp maybe_put_close_key(close_keys, node_key, true), do: MapSet.put(close_keys, node_key)
  defp maybe_put_close_key(close_keys, _node_key, false), do: close_keys

  defp put_revocation(state, wire, revocation) do
    cached_lease = state.leases[revocation.node_key]

    close? =
      is_nil(cached_lease) or cached_lease.lease.policy_revision <= revocation.policy_revision

    leases =
      if close?, do: Map.delete(state.leases, revocation.node_key), else: state.leases

    entry = %{
      wire: wire,
      policy_revision: revocation.policy_revision,
      revoked_at_ms: revocation.revoked_at_ms
    }

    {revocations, _evicted} =
      put_bounded(
        state.revocations,
        revocation.node_key,
        entry,
        state.max_revocations,
        & &1.revoked_at_ms
      )

    {%{state | leases: leases, revocations: revocations}, close?}
  end

  defp verify_revocations(wires, keys, maximum) when length(wires) <= maximum do
    Enum.reduce_while(wires, {:ok, []}, fn wire, {:ok, records} ->
      case Contract.verify_revocation(wire, keys) do
        {:ok, revocation} -> {:cont, {:ok, [{wire, revocation} | records]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp verify_revocations(_wires, _keys, _maximum), do: {:error, :reconciliation_too_large}

  defp verify_lease(state, wire) do
    Contract.verify_lease(wire, state.verification_keys, now_ms(state),
      max_lease_ms: state.max_lease_ms,
      max_future_skew_ms: state.max_future_skew_ms
    )
  end

  defp context(lease, source) do
    %{
      gentility: %{
        source: source,
        node_id: lease.node_id,
        organization_id: lease.organization_id,
        owner_kind: lease.owner_kind,
        deployment_id: lease.deployment_id,
        region_id: lease.region_id,
        policy_revision: lease.policy_revision,
        quota_revision: lease.quota_revision,
        lease_expires_at_ms: lease.expires_at_ms,
        limits: %{
          node_connections: lease.node_connection_limit,
          organization_connections: lease.organization_connection_limit,
          node_bytes_per_second: lease.node_bytes_per_second,
          node_byte_burst: lease.node_byte_burst,
          organization_bytes_per_second: lease.organization_bytes_per_second,
          organization_byte_burst: lease.organization_byte_burst
        }
      }
    }
  end

  defp load_cache(state) do
    case Cache.load(state.cache_path, state.max_cache_entries, state.max_revocations) do
      {:ok, {lease_wires, revocation_wires}} -> load_records(state, lease_wires, revocation_wires)
      {:error, reason} -> %{state | load_error: reason}
    end
  end

  defp load_records(state, lease_wires, revocation_wires) do
    state =
      Enum.reduce(lease_wires, state, fn wire, state ->
        case verify_lease(state, wire) do
          {:ok, lease} -> put_loaded_lease(state, wire, lease)
          {:error, _invalid_or_expired} -> state
        end
      end)

    Enum.reduce(revocation_wires, state, fn wire, state ->
      case Contract.verify_revocation(wire, state.verification_keys) do
        {:ok, revocation} -> elem(put_revocation(state, wire, revocation), 0)
        {:error, _invalid} -> state
      end
    end)
  end

  defp put_loaded_lease(state, wire, lease) do
    sequence = state.sequence + 1
    entry = %{wire: wire, lease: lease, accessed: sequence}
    %{state | leases: Map.put(state.leases, lease.node_key, entry), sequence: sequence}
  end

  defp reverify_records(state) do
    leases =
      Map.new(state.leases, fn {key, entry} ->
        case verify_lease(state, entry.wire) do
          {:ok, lease} -> {key, %{entry | lease: lease}}
          {:error, _reason} -> {key, nil}
        end
      end)

    {invalid_keys, valid_leases} = Enum.split_with(leases, fn {_key, entry} -> is_nil(entry) end)
    Enum.each(invalid_keys, fn {key, _nil} -> close_peer(state, key) end)

    revocations =
      Map.filter(state.revocations, fn {_key, entry} ->
        match?(
          {:ok, _revocation},
          Contract.verify_revocation(entry.wire, state.verification_keys)
        )
      end)

    %{state | leases: Map.new(valid_leases), revocations: revocations}
  end

  defp purge_expired(state) do
    now = now_ms(state)

    {expired, valid} =
      Enum.split_with(state.leases, fn {_key, entry} -> entry.lease.expires_at_ms <= now end)

    if expired == [] do
      state
    else
      Enum.each(expired, fn {key, _entry} -> close_peer(state, key) end)
      state = %{state | leases: Map.new(valid)}
      persist_or_note_error(state)
    end
  end

  defp reschedule_expiry(state) do
    state = cancel_expiry(state)

    case Enum.min_by(state.leases, fn {_key, entry} -> entry.lease.expires_at_ms end, fn ->
           nil
         end) do
      nil ->
        state

      {_key, entry} ->
        delay = max(entry.lease.expires_at_ms - now_ms(state), 0)
        token = make_ref()
        timer = state.clock.send_after(self(), {__MODULE__, :expire, token}, delay)
        %{state | expiry_timer: timer, expiry_token: token}
    end
  end

  defp cancel_expiry(%{expiry_timer: nil} = state), do: state

  defp cancel_expiry(state) do
    _remaining = state.clock.cancel_timer(state.expiry_timer)
    %{state | expiry_timer: nil, expiry_token: nil}
  end

  defp persist_or_note_error(state) do
    case persist(state) do
      :ok -> %{state | persist_error: nil}
      {:error, reason} -> %{state | persist_error: reason}
    end
  end

  defp persist(state) do
    leases =
      state.leases |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(fn {_key, entry} -> entry.wire end)

    revocations =
      state.revocations
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {_key, entry} -> entry.wire end)

    Cache.store(state.cache_path, leases, revocations)
  end

  defp put_bounded(entries, key, entry, maximum, ordering \\ & &1.accessed) do
    entries = Map.put(entries, key, entry)

    if map_size(entries) <= maximum do
      {entries, nil}
    else
      {evicted_key, evicted} = Enum.min_by(entries, fn {_key, value} -> ordering.(value) end)
      {Map.delete(entries, evicted_key), {evicted_key, evicted}}
    end
  end

  defp close_evicted(_state, nil), do: :ok
  defp close_evicted(state, {key, _entry}), do: close_peer(state, key)

  defp close_peer(state, key) do
    _connection_count = state.close_peer.(key)
    :ok
  end

  defp now_ms(state), do: state.clock.system_time(:millisecond)

  defp validate_verification_keys(keys) when map_size(keys) > 0 and map_size(keys) <= 16 do
    if Enum.all?(keys, fn {key_id, key} ->
         is_binary(key_id) and byte_size(key_id) in 1..64 and is_binary(key) and
           byte_size(key) == 32
       end) do
      :ok
    else
      {:error, :invalid_verification_keys}
    end
  end

  defp validate_verification_keys(_keys), do: {:error, :invalid_verification_keys}

  defp positive_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a positive integer"
    end
  end

  defp non_negative_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value >= 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a non-negative integer"
    end
  end
end
