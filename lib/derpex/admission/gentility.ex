defmodule Derpex.Admission.Gentility do
  @moduledoc """
  Bounded Gentility admission leases, outage reconnects, and active revocation.

  Live authorization is attempted outside the controller process so expiry and
  revocation remain responsive during a control-plane outage. An atomic gate
  rejects excess work before it can enter the controller mailbox.

  An authority answer is authoritative only when it is a signed contract v1
  record: a lease admits, and a revocation denies. Every other answer — an
  error tuple of any shape, a timeout, an exit, or an unrecognized term — is a
  failure of the control plane, never a denial, so admission falls back to the
  cached lease. A node with no unexpired cached lease is still rejected.
  """

  use GenServer

  @behaviour Derpex.Admission

  alias Derpex.Admission.Gentility.ByteBudget
  alias Derpex.Admission.Gentility.Cache
  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation
  alias Derpex.Admission.Gentility.Usage
  alias Derpex.Admission.Gentility.UsageWorker
  alias Derpex.Admission.Request
  alias Derpex.Clock
  alias Derpex.Router

  @default_max_cache_entries 100_000
  @default_max_revocations 10_000
  @default_max_concurrent_requests 64
  @default_authority_timeout 2_000
  @default_max_lease_ms 15 * 60 * 1_000
  @default_max_future_skew_ms 30_000
  @default_max_byte_delay_ms 30_000
  defmodule Policy do
    @moduledoc "An immutable, lock-free admission handle obtained from a running controller."

    @enforce_keys [
      :server,
      :authority,
      :gate,
      :max_concurrent_requests,
      :authority_timeout,
      :byte_budgets,
      :clock,
      :max_byte_delay_ms,
      :usage
    ]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            server: GenServer.server(),
            authority: term(),
            gate: :atomics.atomics_ref(),
            max_concurrent_requests: pos_integer(),
            authority_timeout: pos_integer(),
            byte_budgets: :ets.tid(),
            clock: module(),
            max_byte_delay_ms: pos_integer(),
            usage: nil | map()
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

  @impl Derpex.Admission
  def claim(%Request{} = request, context, connection, %Policy{} = policy)
      when is_map(context) and is_pid(connection) do
    controller_call(policy.server, {:claim, request.node_key, context, connection})
  end

  def claim(%Request{} = request, context, connection, server) do
    claim(request, context, connection, policy(server))
  catch
    :exit, _reason -> {:error, :admission_unavailable}
  end

  @impl Derpex.Admission
  def release(connection, %Policy{} = policy) when is_pid(connection) do
    _result = controller_call(policy.server, {:release, connection})
    :ok
  end

  def release(connection, server) when is_pid(connection) do
    _result = controller_call(server, {:release, connection})
    :ok
  end

  @impl Derpex.Admission
  def reserve_bytes(%{gentility: gentility}, bytes, %Policy{} = policy)
      when is_integer(bytes) and bytes >= 0 do
    now = policy.clock.monotonic_time(:microsecond)

    with :ok <- usage_available(policy.usage),
         {:ok, node_delay} <-
           ByteBudget.reserve(policy.byte_budgets, :node, gentility.node_key, bytes, now),
         {:ok, organization_delay} <-
           ByteBudget.reserve(
             policy.byte_budgets,
             :organization,
             gentility.organization_id,
             bytes,
             now
           ) do
      delay = max(node_delay, organization_delay)

      if delay <= policy.max_byte_delay_ms * 1_000,
        do: {:ok, delay},
        else: {:error, :byte_budget_exhausted}
    end
  end

  def reserve_bytes(_context, _bytes, %Policy{}), do: {:error, :invalid_admission_context}

  def reserve_bytes(context, bytes, server) do
    reserve_bytes(context, bytes, policy(server))
  catch
    :exit, _reason -> {:error, :admission_unavailable}
  end

  @impl Derpex.Admission
  def record_usage(_context, _bytes, _outcome, %Policy{usage: nil}), do: :ok

  def record_usage(%{gentility: gentility}, bytes, outcome, %Policy{} = policy)
      when is_integer(bytes) and bytes >= 0 and outcome in [:accepted, :dropped] do
    with :ok <- usage_available(policy.usage) do
      Usage.record(
        policy.usage.table,
        policy.usage.window_ms,
        gentility,
        bytes,
        outcome,
        policy.clock.system_time(:millisecond)
      )
    end
  end

  def record_usage(_context, _bytes, _outcome, %Policy{}),
    do: {:error, :invalid_admission_context}

  def record_usage(context, bytes, outcome, server) do
    record_usage(context, bytes, outcome, policy(server))
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
  def stats(server) do
    {stats, usage} = GenServer.call(server, :stats)
    Map.put(stats, :usage, UsageWorker.stats(usage))
  end

  @impl GenServer
  def init(options) do
    with {:ok, state} <- initial_state(options) do
      state = state |> load_cache() |> purge_expired() |> reschedule_expiry()
      {:ok, state}
    end
  end

  @impl GenServer
  def handle_call(:policy, _from, state), do: {:reply, state.policy, state}

  def handle_call(:stats, _from, state) do
    reply = %{
      cache_entries: map_size(state.leases),
      revocations: map_size(state.revocations),
      active_connections: map_size(state.claims),
      active_nodes: map_size(state.node_connections),
      active_organizations: map_size(state.organization_connections),
      active_requests: :atomics.get(state.policy.gate, 1),
      max_cache_entries: state.max_cache_entries,
      max_revocations: state.max_revocations,
      cache_full: state.cache_full,
      load_error: state.load_error,
      persist_error: state.persist_error
    }

    {:reply, {reply, state.usage}, state}
  end

  def handle_call({:accept_live, node_key, wire}, _from, state) do
    state = purge_expired(state)

    case Contract.record_type(wire) do
      {:ok, :lease} -> accept_live_lease(state, node_key, wire)
      {:ok, :revocation} -> accept_live_denial(state, node_key, wire)
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:cached, node_key}, _from, state) do
    state |> purge_expired() |> cached_decision(node_key)
  end

  def handle_call({:claim, node_key, context, connection}, _from, state) do
    state = purge_expired(state)
    claim_connection(state, node_key, context, connection)
  end

  def handle_call({:release, connection}, _from, state) do
    {:reply, :ok, release_connection(state, connection, true)}
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

  def handle_info({:DOWN, monitor, :process, connection, _reason}, state) do
    case state.claims[connection] do
      %{monitor: ^monitor} -> {:noreply, release_connection(state, connection, false)}
      _unknown -> {:noreply, state}
    end
  end

  @impl GenServer
  def terminate(_reason, state) do
    cancel_expiry(state)
    UsageWorker.stop(state.usage)
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

    max_byte_delay_ms =
      positive_option!(options, :max_byte_delay_ms, @default_max_byte_delay_ms)

    verification_keys = Keyword.fetch!(options, :verification_keys)
    clock = Keyword.get(options, :clock, Clock)

    with :ok <- validate_verification_keys(verification_keys),
         {:ok, usage} <- initial_usage(Keyword.get(options, :usage), clock) do
      byte_budgets = ByteBudget.new()

      policy = %Policy{
        server: server,
        authority: authority,
        gate: gate,
        max_concurrent_requests: max_concurrent_requests,
        authority_timeout: authority_timeout,
        byte_budgets: byte_budgets,
        clock: clock,
        max_byte_delay_ms: max_byte_delay_ms,
        usage: usage_policy(usage)
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
         clock: clock,
         close_peer: Keyword.get(options, :close_peer, &Router.close_peer/1),
         close_connection:
           Keyword.get(options, :close_connection, fn connection, reason ->
             send(connection, {:derpex_admission_close, reason})
           end),
         leases: %{},
         revocations: %{},
         claims: %{},
         node_connections: %{},
         organization_connections: %{},
         node_budgets: %{},
         organization_budgets: %{},
         closing_connections: MapSet.new(),
         cache_full: 0,
         sequence: 0,
         expiry_timer: nil,
         expiry_token: nil,
         load_error: nil,
         persist_error: nil,
         usage: usage
       }}
    end
  end

  defp authorize_reserved(request, policy) do
    case invoke_with_timeout(policy.authority, request, policy.authority_timeout) do
      {:ok, {:ok, wire}} when is_binary(wire) ->
        controller_call(policy.server, {:accept_live, request.node_key, wire})

      _authority_failed ->
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

  defp accept_live_lease(state, node_key, wire) do
    case verify_lease(state, wire) do
      {:ok, %Lease{node_key: ^node_key} = lease} ->
        accept_verified_lease(state, wire, lease)

      {:ok, %Lease{}} ->
        {:reply, {:error, :lease_node_key_mismatch}, state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  # A revocation denies only the leases it covers. One whose policy revision is
  # older than the cached lease, or one already superseded in the revocation
  # table, leaves that lease standing, so the authorization continues with the
  # cached decision rather than reporting a revocation that did not apply.
  defp accept_live_denial(state, node_key, wire) do
    case Contract.verify_revocation(wire, state.verification_keys) do
      {:ok, %Revocation{node_key: ^node_key} = revocation} ->
        case revoke_record(state, wire, revocation) do
          {:covered, state} -> {:reply, {:error, :lease_revoked}, state}
          {_uncovered_or_stale, state} -> cached_decision(state, node_key)
        end

      {:ok, %Revocation{}} ->
        {:reply, {:error, :revocation_node_key_mismatch}, state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  defp cached_decision(state, node_key) do
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

  defp accept_verified_lease(state, wire, lease) do
    revoked_revision =
      state.revocations |> Map.get(lease.node_key, %{}) |> Map.get(:policy_revision, -1)

    cond do
      lease.policy_revision <= revoked_revision ->
        {:reply, {:error, :lease_revoked}, state}

      stale_lease?(state.leases[lease.node_key], lease) ->
        {:reply, {:error, :stale_lease}, state}

      true ->
        install_live_lease(state, wire, lease)
    end
  end

  defp install_live_lease(state, wire, lease) do
    sequence = state.sequence + 1
    entry = %{wire: wire, lease: lease, accessed: sequence}

    case admit_lease(state, lease.node_key, entry) do
      {:ok, leases, evicted} ->
        install_admitted_lease(state, lease, leases, evicted, sequence)

      {:error, :cache_full} ->
        {:reply, {:error, :cache_full}, %{state | cache_full: state.cache_full + 1}}
    end
  end

  defp install_admitted_lease(state, lease, leases, evicted, sequence) do
    revocations = Map.delete(state.revocations, lease.node_key)

    candidate =
      %{state | leases: leases, revocations: revocations, sequence: sequence}
      |> rebuild_budgets()

    close_evicted(candidate, evicted)
    candidate = enforce_revised_budgets(candidate)

    case persist(candidate) do
      :ok ->
        state = %{candidate | persist_error: nil} |> reschedule_expiry()
        {:reply, {:ok, context(lease, :live)}, state}

      {:error, reason} ->
        state = %{candidate | persist_error: reason} |> reschedule_expiry()
        {:reply, {:error, {:cache_persist, reason}}, state}
    end
  end

  # Admits a lease into the bounded cache. An entry an active connection is
  # claiming is never evicted while its lease is valid, so a saturated cache
  # rejects the new admission instead of closing an established peer.
  defp admit_lease(state, node_key, entry) do
    leases = Map.put(state.leases, node_key, entry)

    if map_size(leases) <= state.max_cache_entries do
      {:ok, leases, nil}
    else
      case evictable_lease(state, leases, node_key) do
        nil -> {:error, :cache_full}
        {key, evicted} -> {:ok, Map.delete(leases, key), {key, evicted}}
      end
    end
  end

  defp evictable_lease(state, leases, admitted_key) do
    now = now_ms(state)

    leases
    |> Enum.reject(fn {key, entry} ->
      key == admitted_key or (entry.lease.expires_at_ms > now and claimed?(state, key))
    end)
    |> Enum.min_by(fn {_key, entry} -> {entry.lease.expires_at_ms, entry.accessed} end, fn ->
      nil
    end)
  end

  defp claimed?(state, node_key), do: Map.get(state.node_connections, node_key, 0) > 0

  defp stale_lease?(nil, _lease), do: false

  defp stale_lease?(%{lease: current}, lease) do
    current.policy_revision > lease.policy_revision or
      (current.policy_revision == lease.policy_revision and
         current.quota_revision > lease.quota_revision)
  end

  defp apply_one_revocation(state, wire, revocation) do
    case revoke_record(state, wire, revocation) do
      {:stale, state} -> {:reply, {:ok, :stale}, state}
      {_covered_or_uncovered, state} -> {:reply, {:ok, :applied}, state}
    end
  end

  # Stores one authenticated revocation. A replay of a revision the table already
  # holds is not stored again, so a repeated record cannot churn the bounded
  # revocation table. `:covered` means the record invalidated the cached lease
  # and closed the node; `:uncovered` means a newer cached lease survives it.
  defp revoke_record(state, wire, revocation) do
    case state.revocations[revocation.node_key] do
      %{policy_revision: revision} when revision >= revocation.policy_revision ->
        {:stale, state}

      _older_or_missing ->
        {state, close?} = put_revocation(state, wire, revocation)
        if close?, do: close_peer(state, revocation.node_key)
        state = persist_or_note_error(state) |> reschedule_expiry()
        {if(close?, do: :covered, else: :uncovered), state}
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

    revocations =
      put_bounded_revocation(
        state.revocations,
        revocation.node_key,
        entry,
        state.max_revocations
      )

    {%{state | leases: leases, revocations: revocations} |> rebuild_budgets(), close?}
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
        node_key: lease.node_key,
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

  defp claim_connection(state, node_key, context, connection) do
    case state.claims[connection] do
      %{node_key: ^node_key} ->
        {:reply, {:ok, context}, state}

      nil ->
        claim_unregistered_connection(state, node_key, context, connection)

      _different_claim ->
        {:reply, {:error, :connection_already_claimed}, state}
    end
  end

  defp claim_unregistered_connection(state, node_key, context, connection) do
    with {:ok, lease} <- claim_lease(state, node_key, context),
         :ok <- connection_budget_available(state, lease) do
      sequence = state.sequence + 1

      claim = %{
        monitor: Process.monitor(connection),
        node_key: node_key,
        organization_id: lease.organization_id,
        sequence: sequence,
        node_budget: node_budget(lease),
        organization_budget: organization_budget(lease)
      }

      state = %{
        state
        | claims: Map.put(state.claims, connection, claim),
          node_connections: increment(state.node_connections, node_key),
          organization_connections:
            increment(state.organization_connections, lease.organization_id),
          sequence: sequence
      }

      {:reply, {:ok, context}, rebuild_budgets(state)}
    else
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  defp claim_lease(state, node_key, %{gentility: %{organization_id: organization_id}}) do
    case state.leases[node_key] do
      %{lease: %Lease{organization_id: ^organization_id} = lease} -> {:ok, lease}
      %{lease: %Lease{}} -> {:error, :admission_context_mismatch}
      nil -> {:error, :lease_not_cached}
    end
  end

  defp claim_lease(_state, _node_key, _context), do: {:error, :invalid_admission_context}

  defp connection_budget_available(state, lease) do
    node_limit = state.node_budgets[lease.node_key].connection_limit
    organization_limit = state.organization_budgets[lease.organization_id].connection_limit
    node_count = Map.get(state.node_connections, lease.node_key, 0)
    organization_count = Map.get(state.organization_connections, lease.organization_id, 0)

    cond do
      node_count >= node_limit -> {:error, :node_connection_limit}
      organization_count >= organization_limit -> {:error, :organization_connection_limit}
      true -> :ok
    end
  end

  defp release_connection(state, connection, demonitor?) do
    case Map.pop(state.claims, connection) do
      {nil, _claims} ->
        state

      {claim, claims} ->
        if demonitor?, do: Process.demonitor(claim.monitor, [:flush])

        %{
          state
          | claims: claims,
            node_connections: decrement(state.node_connections, claim.node_key),
            organization_connections:
              decrement(state.organization_connections, claim.organization_id),
            closing_connections: MapSet.delete(state.closing_connections, connection)
        }
        |> rebuild_budgets()
    end
  end

  defp increment(counts, key), do: Map.update(counts, key, 1, &(&1 + 1))

  defp decrement(counts, key) do
    case Map.get(counts, key, 0) do
      count when count <= 1 -> Map.delete(counts, key)
      count -> Map.put(counts, key, count - 1)
    end
  end

  defp rebuild_budgets(state) do
    {node_budgets, organization_budgets} =
      Enum.reduce(state.leases, {%{}, %{}}, fn {_key, entry}, budgets ->
        merge_budgets(budgets, node_budget(entry.lease), organization_budget(entry.lease))
      end)

    {node_budgets, organization_budgets} =
      Enum.reduce(state.claims, {node_budgets, organization_budgets}, fn {_pid, claim}, budgets ->
        merge_budgets(budgets, claim.node_budget, claim.organization_budget)
      end)

    state = %{state | node_budgets: node_budgets, organization_budgets: organization_budgets}
    sync_byte_budgets(state)
  end

  defp sync_byte_budgets(state) do
    now = state.clock.monotonic_time(:microsecond)

    Enum.each(state.node_budgets, fn {_identity, budget} ->
      ByteBudget.sync(state.policy.byte_budgets, :node, budget, now)
    end)

    Enum.each(state.organization_budgets, fn {_identity, budget} ->
      ByteBudget.sync(state.policy.byte_budgets, :organization, budget, now)
    end)

    retained =
      Enum.reduce(state.node_budgets, MapSet.new(), fn {identity, _budget}, retained ->
        MapSet.put(retained, {:node, identity})
      end)

    retained =
      Enum.reduce(state.organization_budgets, retained, fn {identity, _budget}, retained ->
        MapSet.put(retained, {:organization, identity})
      end)

    :ok = ByteBudget.prune(state.policy.byte_budgets, retained)
    state
  end

  defp merge_budgets({node_budgets, organization_budgets}, node, organization) do
    {
      put_newer_budget(node_budgets, node.identity, node),
      put_newer_budget(organization_budgets, organization.identity, organization)
    }
  end

  defp put_newer_budget(budgets, identity, budget) do
    case budgets[identity] do
      %{revision: revision} when revision > budget.revision ->
        budgets

      %{revision: revision} = current when revision == budget.revision ->
        Map.put(budgets, identity, stricter_budget(current, budget))

      _older_or_missing ->
        Map.put(budgets, identity, budget)
    end
  end

  defp stricter_budget(left, right) do
    %{
      left
      | connection_limit: min(left.connection_limit, right.connection_limit),
        bytes_per_second: stricter_rate(left.bytes_per_second, right.bytes_per_second),
        byte_burst: min(left.byte_burst, right.byte_burst)
    }
  end

  defp stricter_rate(0, rate), do: rate
  defp stricter_rate(rate, 0), do: rate
  defp stricter_rate(left, right), do: min(left, right)

  defp node_budget(lease) do
    %{
      identity: lease.node_key,
      revision: lease.quota_revision,
      connection_limit: lease.node_connection_limit,
      bytes_per_second: lease.node_bytes_per_second,
      byte_burst: lease.node_byte_burst
    }
  end

  defp organization_budget(lease) do
    %{
      identity: lease.organization_id,
      revision: lease.quota_revision,
      connection_limit: lease.organization_connection_limit,
      bytes_per_second: lease.organization_bytes_per_second,
      byte_burst: lease.organization_byte_burst
    }
  end

  defp enforce_revised_budgets(state) do
    state
    |> over_limit_connections()
    |> Enum.reject(&MapSet.member?(state.closing_connections, &1))
    |> Enum.reduce(state, fn connection, state ->
      state.close_connection.(connection, :quota_revision)
      %{state | closing_connections: MapSet.put(state.closing_connections, connection)}
    end)
  end

  defp over_limit_connections(state) do
    node_excess =
      Enum.flat_map(state.node_connections, fn {node_key, count} ->
        limit = state.node_budgets[node_key].connection_limit
        newest_claims(state, fn claim -> claim.node_key == node_key end, max(count - limit, 0))
      end)

    organization_excess =
      Enum.flat_map(state.organization_connections, fn {organization_id, count} ->
        limit = state.organization_budgets[organization_id].connection_limit

        newest_claims(
          state,
          fn claim -> claim.organization_id == organization_id end,
          max(count - limit, 0)
        )
      end)

    Enum.uniq(node_excess ++ organization_excess)
  end

  defp newest_claims(_state, _filter, 0), do: []

  defp newest_claims(state, filter, count) do
    state.claims
    |> Enum.filter(fn {_connection, claim} -> filter.(claim) end)
    |> Enum.sort_by(fn {_connection, claim} -> claim.sequence end, :desc)
    |> Enum.take(count)
    |> Enum.map(&elem(&1, 0))
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

    revocation_wires
    |> Enum.reduce(state, fn wire, state ->
      case Contract.verify_revocation(wire, state.verification_keys) do
        {:ok, revocation} -> elem(put_revocation(state, wire, revocation), 0)
        {:error, _invalid} -> state
      end
    end)
    |> rebuild_budgets()
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

    %{state | leases: Map.new(valid_leases), revocations: revocations} |> rebuild_budgets()
  end

  defp purge_expired(state) do
    now = now_ms(state)

    {expired, valid} =
      Enum.split_with(state.leases, fn {_key, entry} -> entry.lease.expires_at_ms <= now end)

    if expired == [] do
      state
    else
      Enum.each(expired, fn {key, _entry} -> close_peer(state, key) end)
      state = %{state | leases: Map.new(valid)} |> rebuild_budgets()
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

  # Revocations are bounded by revocation time: the oldest record is the one
  # Gentility is soonest to prune, and every lease it could still deny has
  # expired by then.
  defp put_bounded_revocation(entries, key, entry, maximum) do
    entries = Map.put(entries, key, entry)

    if map_size(entries) <= maximum do
      entries
    else
      {evicted_key, _evicted} =
        Enum.min_by(entries, fn {_key, value} -> value.revoked_at_ms end)

      Map.delete(entries, evicted_key)
    end
  end

  defp close_evicted(_state, nil), do: :ok
  defp close_evicted(state, {key, _entry}), do: close_peer(state, key)

  defp close_peer(state, key) do
    _connection_count = state.close_peer.(key)
    :ok
  end

  defp initial_usage(nil, _clock), do: {:ok, nil}

  defp initial_usage(options, clock) when is_list(options) do
    options = options |> Keyword.put(:clock, clock) |> Keyword.put(:owner, self())

    with {:ok, server} <- UsageWorker.start_link(options) do
      {:ok, UsageWorker.handle(server)}
    end
  end

  defp initial_usage(_options, _clock), do: {:error, :invalid_usage_options}

  defp usage_policy(nil), do: nil

  defp usage_policy(usage) do
    %{
      server: usage.server,
      table: usage.table,
      blocked: usage.blocked,
      window_ms: usage.window_ms
    }
  end

  defp usage_available(nil), do: :ok

  defp usage_available(usage) do
    if :atomics.get(usage.blocked, 1) == 0,
      do: :ok,
      else: {:error, :usage_spool_full}
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
