defmodule Derpex.Admission.Gentility do
  @moduledoc """
  Bounded Gentility admission leases, outage reconnects, and active revocation.

  Live authorization is attempted outside the controller process so expiry and
  revocation remain responsive during a control-plane outage. An atomic gate
  rejects excess work before it can enter the controller mailbox.

  Allocations are incremental: a claim or a release touches only the node and
  organization it names, expiry order is kept in a tree rather than rescanned,
  and stale token-bucket rows are reclaimed on a timer. No admission decision
  walks the lease cache.

  An authority answer is authoritative only when it is a signed contract v1
  record: a lease admits, and a revocation denies. Every other answer — an
  error tuple of any shape, a timeout, an exit, or an unrecognized term — is a
  failure of the control plane, never a denial, so admission falls back to the
  cached lease. A node with no unexpired cached lease is still rejected.
  """

  use GenServer

  require Logger

  @behaviour Derpex.Admission

  alias Derpex.Admission.Gentility.Budgets
  alias Derpex.Admission.Gentility.ByteBudget
  alias Derpex.Admission.Gentility.Cache
  alias Derpex.Admission.Gentility.CacheWriter
  alias Derpex.Admission.Gentility.Closer
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
  @default_budget_prune_ms 30_000
  @default_cache_persist_ms 5_000
  @default_renewal_retry_ms 60_000
  @renewal_fraction {4, 5}
  @expiry_jitter_percent 10
  @default_log_interval_ms 60_000
  @denial_reasons [
    :no_cached_lease,
    :lease_revoked,
    :cache_full,
    :stale_lease,
    :wrong_region,
    :invalid_record,
    :overloaded,
    :unavailable,
    :other
  ]
  @close_peer_causes [:expiry, :revocation, :eviction, :key_rotation]
  @cache_write_timeout_ms 2_000
  @budget_prune_chunk 1_000
  @reverify_chunk 1_000
  defmodule Policy do
    @moduledoc "An immutable, lock-free admission handle obtained from a running controller."

    @enforce_keys [
      :server,
      :authority,
      :gate,
      :counters,
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
            counters: :atomics.atomics_ref(),
            max_concurrent_requests: pos_integer(),
            authority_timeout: pos_integer(),
            byte_budgets: :ets.tid(),
            clock: module(),
            max_byte_delay_ms: pos_integer(),
            usage: nil | map()
          }
  end

  @overloaded_counter 1
  @unavailable_counter 2
  @usage_shed_counter 3

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
    case reserve(policy.gate, policy.max_concurrent_requests) do
      :ok ->
        try do
          authorize_reserved(request, policy)
        after
          :atomics.sub(policy.gate, 1, 1)
        end

      {:error, :admission_overloaded} = shed ->
        :atomics.add(policy.counters, @overloaded_counter, 1)
        shed
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

    with :ok <- usage_available(policy),
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
      maximum_delay = policy.max_byte_delay_ms * 1_000

      # Only a node's own debt may close its connection. An organization's debt
      # paces every sibling instead: one noisy node must not disconnect the
      # quiet ones it shares an organization with. Pacing is capped so a paced
      # connection stays responsive; the untaken debt keeps pacing the next
      # reservation.
      if node_delay <= maximum_delay do
        {:ok, min(max(node_delay, organization_delay), maximum_delay)}
      else
        {:error, :byte_budget_exhausted}
      end
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
    with :ok <- usage_available(policy) do
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
    # Trapping exits is what makes the final cache write on shutdown possible.
    Process.flag(:trap_exit, true)

    case initial_state(options) do
      {:ok, state} ->
        state =
          state
          |> load_cache()
          |> purge_expired()
          |> reschedule_timers()
          |> schedule_budget_prune()

        {:ok, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call(:policy, _from, state), do: {:reply, state.policy, state}

  def handle_call(:stats, _from, state) do
    budgets = Budgets.stats(state.budgets)

    reply = %{
      cache_entries: map_size(state.leases),
      revocations: map_size(state.revocations),
      active_connections: map_size(state.claims),
      active_nodes: map_size(state.node_claims),
      active_organizations: map_size(state.organization_claims),
      active_requests: :atomics.get(state.policy.gate, 1),
      max_cache_entries: state.max_cache_entries,
      max_revocations: state.max_revocations,
      cache_full: state.cache_full,
      budget_nodes: budgets.nodes,
      budget_organizations: budgets.organizations,
      renewals_in_flight: map_size(state.renewals),
      authorize_counts: caller_counts(state, state.authorize_counts),
      close_peer_counts: state.close_peer_counts,
      nearest_lease_expiry_seconds: nearest_lease_expiry_seconds(state),
      usage_shed_total: :atomics.get(state.policy.counters, @usage_shed_counter),
      cache_load_error: state.load_error != nil,
      cache_persist_error: state.persist_error != nil,
      load_error: state.load_error,
      persist_error: state.persist_error
    }

    {:reply, {reply, state.usage}, state}
  end

  def handle_call({:accept_live, node_key, wire}, _from, state) do
    state = purge_expired(state)

    case Contract.record_type(wire) do
      {:ok, :lease} -> counted(accept_live_lease(state, node_key, wire))
      {:ok, :revocation} -> counted(accept_live_denial(state, node_key, wire))
      {:error, _reason} = error -> counted({:reply, error, state})
    end
  end

  def handle_call({:cached, node_key}, _from, state) do
    state |> purge_expired() |> cached_decision(node_key) |> counted()
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
        {:reply, :ok, start_reverify(%{state | verification_keys: keys})}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_info({__MODULE__, :expire, token}, %{expiry_token: token} = state) do
    state = %{state | expiry_timer: nil, expiry_token: nil}
    {:noreply, state |> purge_expired() |> reschedule_timers()}
  end

  def handle_info({__MODULE__, :expire, _stale}, state), do: {:noreply, state}

  def handle_info({__MODULE__, :renew, token}, %{renewal_token: token} = state) do
    state = %{state | renewal_timer: nil, renewal_token: nil}
    {:noreply, state |> renew_due() |> reschedule_renewal()}
  end

  def handle_info({__MODULE__, :renew, _stale}, state), do: {:noreply, state}

  def handle_info({__MODULE__, :renewed, pid, node_key, result}, state) do
    state = finish_renewal(state, pid)

    state =
      state
      |> apply_renewal(node_key, result)
      |> reschedule_timers()

    {:noreply, state}
  end

  def handle_info({__MODULE__, :prune_budgets, token}, %{budget_prune_token: token} = state) do
    {:noreply, step_budget_prune(%{state | budget_prune_timer: nil}, :start)}
  end

  def handle_info({__MODULE__, :prune_budgets, _stale}, state), do: {:noreply, state}

  def handle_info(
        {__MODULE__, :prune_budgets_step, token},
        %{budget_prune_token: token} = state
      ) do
    {:noreply, step_budget_prune(state, state.budget_prune_cursor)}
  end

  def handle_info({__MODULE__, :prune_budgets_step, _stale}, state), do: {:noreply, state}

  def handle_info({__MODULE__, :persist_cache, token}, %{cache_persist_token: token} = state) do
    {:noreply, flush_cache(%{state | cache_persist_timer: nil, cache_persist_token: nil})}
  end

  def handle_info({__MODULE__, :persist_cache, _stale}, state), do: {:noreply, state}

  def handle_info({__MODULE__, :reverify, token}, %{reverify: %{token: token}} = state) do
    {:noreply, reverify_chunk(state)}
  end

  def handle_info({__MODULE__, :reverify, _stale}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, pid, _reason}, state) do
    cond do
      match?(%{monitor: ^monitor}, state.renewals[pid]) ->
        node_key = state.renewals[pid].node_key
        state = finish_renewal(%{state | renewals: Map.delete(state.renewals, pid)}, nil)
        {:noreply, state |> requeue_renewal_for(node_key) |> reschedule_renewal()}

      match?(%{monitor: ^monitor}, state.claims[pid]) ->
        {:noreply, release_connection(state, pid, false)}

      true ->
        {:noreply, state}
    end
  end

  def handle_info({CacheWriter, :write_result, :ok}, state) do
    {:noreply, %{state | persist_error: nil}}
  end

  def handle_info({CacheWriter, :write_result, {:error, reason}}, state) do
    state =
      log_event(
        %{state | persist_error: reason},
        :cache_persist_error,
        "gentility admission cache write failed: #{inspect(reason)}"
      )

    {:noreply, mark_cache_dirty(state)}
  end

  # The usage worker and the cache writer are linked, so their exits still take
  # the controller down. Trapping exits only converts the signal into a message.
  def handle_info({:EXIT, pid, reason}, state) do
    cond do
      state.usage && state.usage.server == pid -> {:stop, reason, state}
      state.cache_writer == pid -> {:stop, reason, state}
      state.closer == pid -> {:stop, reason, state}
      true -> unexpected_exit(state, pid, reason)
    end
  end

  @impl GenServer
  def terminate(_reason, state) do
    cancel_expiry(state)
    cancel_renewal(state)
    cancel_budget_prune(state)
    _flushed = flush_cache(state, :sync)
    UsageWorker.stop(state.usage)
    CacheWriter.stop(state.cache_writer)
    Closer.stop(state.closer)
    :ok
  end

  defp initial_state(options) do
    authority = Keyword.fetch!(options, :authority)
    server = Keyword.get(options, :server) || self()
    gate = :atomics.new(1, signed: false)
    counters = :atomics.new(3, signed: false)

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

    budget_prune_ms = positive_option!(options, :budget_prune_ms, @default_budget_prune_ms)

    cache_persist_ms =
      positive_option!(options, :cache_persist_ms, @default_cache_persist_ms)

    renewal_retry_ms = positive_option!(options, :renewal_retry_ms, @default_renewal_retry_ms)
    log_interval_ms = non_negative_option!(options, :log_interval_ms, @default_log_interval_ms)
    expiry_jitter = Keyword.get(options, :expiry_jitter, &default_expiry_jitter/1)

    verification_keys = Keyword.fetch!(options, :verification_keys)
    region_id = region_option!(options)
    clock = Keyword.get(options, :clock, Clock)

    cache_path = Keyword.get(options, :cache_path)

    close_peer = Keyword.get(options, :close_peer, &Router.close_peer/1)

    with :ok <- validate_verification_keys(verification_keys),
         {:ok, cache_writer} <- initial_cache_writer(cache_path),
         {:ok, closer} <- Closer.start_link(close_peer: close_peer),
         {:ok, usage} <- initial_usage(Keyword.get(options, :usage), clock) do
      budgets = Budgets.new()

      policy = %Policy{
        server: server,
        authority: authority,
        gate: gate,
        counters: counters,
        max_concurrent_requests: max_concurrent_requests,
        authority_timeout: authority_timeout,
        byte_budgets: Budgets.table(budgets),
        clock: clock,
        max_byte_delay_ms: max_byte_delay_ms,
        usage: usage_policy(usage)
      }

      {:ok,
       %{
         policy: policy,
         verification_keys: verification_keys,
         cache_path: cache_path,
         max_cache_entries: max_cache_entries,
         max_revocations: max_revocations,
         max_lease_ms: max_lease_ms,
         max_future_skew_ms: max_future_skew_ms,
         region_id: region_id,
         clock: clock,
         close_peer: close_peer,
         closer: closer,
         close_connection:
           Keyword.get(options, :close_connection, fn connection, reason ->
             send(connection, {:derpex_admission_close, reason})
           end),
         leases: %{},
         by_expiry: :gb_trees.empty(),
         unclaimed: :gb_trees.empty(),
         revocations: %{},
         revocations_by_time: :gb_trees.empty(),
         claims: %{},
         node_claims: %{},
         organization_claims: %{},
         budgets: budgets,
         budget_prune_ms: budget_prune_ms,
         budget_prune_timer: nil,
         budget_prune_token: nil,
         budget_prune_cursor: :start,
         cache_persist_ms: cache_persist_ms,
         cache_persist_timer: nil,
         cache_persist_token: nil,
         cache_dirty: false,
         cache_writer: cache_writer,
         reverify: nil,
         by_renewal: :gb_trees.empty(),
         renewal_timer: nil,
         renewal_token: nil,
         renewal_retry_ms: renewal_retry_ms,
         renewals: %{},
         expiry_jitter: expiry_jitter,
         authorize_counts: %{},
         close_peer_counts: %{},
         log_interval_ms: log_interval_ms,
         log_at: %{},
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
        controller_call(policy.server, {:accept_live, request.node_key, wire}, policy)

      _authority_failed ->
        controller_call(policy.server, {:cached, request.node_key}, policy)
    end
  end

  @doc false
  @spec authorize_labels() :: [{atom(), atom()}]
  def authorize_labels do
    [{:live, :ok}, {:cached, :ok}] ++ Enum.map(@denial_reasons, &{:denied, &1})
  end

  @doc false
  @spec close_peer_causes() :: [atom()]
  def close_peer_causes, do: @close_peer_causes

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

  defp controller_call(server, message, %Policy{} = policy) do
    case controller_call(server, message) do
      {:error, :admission_unavailable} = unavailable ->
        :atomics.add(policy.counters, @unavailable_counter, 1)
        unavailable

      result ->
        result
    end
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

  # Every authorization the controller answers is counted under a fixed label
  # set, so the outcome mix is visible without a per-node series.
  defp counted({:reply, reply, state}) do
    {outcome, reason} = authorize_label(reply)
    {:reply, reply, count_authorize(state, outcome, reason)}
  end

  defp authorize_label({:ok, %{gentility: %{source: :live}}}), do: {:live, :ok}
  defp authorize_label({:ok, %{gentility: %{source: :cached}}}), do: {:cached, :ok}
  defp authorize_label({:error, reason}), do: {:denied, denial_reason(reason)}

  defp denial_reason(reason) when reason in @denial_reasons, do: reason
  defp denial_reason(:admission_unavailable), do: :unavailable
  defp denial_reason(:lease_not_cached), do: :no_cached_lease
  defp denial_reason(:admission_overloaded), do: :overloaded
  defp denial_reason(reason) when is_atom(reason), do: record_reason(reason)
  defp denial_reason({:unknown_signing_key, _key_id}), do: :invalid_record
  defp denial_reason({:invalid_signing_key, _key_id}), do: :invalid_record
  defp denial_reason({:unsupported_version, _version}), do: :invalid_record
  defp denial_reason({:invalid_field, _field}), do: :invalid_record
  defp denial_reason(_reason), do: :other

  defp record_reason(reason) do
    if reason |> Atom.to_string() |> String.contains?(["lease", "record", "signature", "utf8"]),
      do: :invalid_record,
      else: :other
  end

  defp count_authorize(state, outcome, reason) do
    counts = Map.update(state.authorize_counts, {outcome, reason}, 1, &(&1 + 1))
    %{state | authorize_counts: counts}
  end

  defp cached_decision(state, node_key) do
    case state.leases[node_key] do
      nil ->
        {:reply, {:error, :no_cached_lease}, reschedule_timers(state)}

      entry ->
        state =
          log_event(
            state,
            :serving_cached,
            "gentility authority unavailable; serving cached admission leases"
          )

        {:reply, {:ok, context(entry.lease, :cached)}, reschedule_timers(state)}
    end
  end

  # Every one of these conditions can repeat per connection attempt, so the log
  # is rate limited per kind while the counters behind it stay exact.
  defp log_event(state, event, message) do
    now = now_ms(state)
    last = Map.get(state.log_at, event)

    if is_nil(last) or now - last >= state.log_interval_ms do
      Logger.warning(message)
      %{state | log_at: Map.put(state.log_at, event, now)}
    else
      state
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

  # Admits a lease into the bounded cache. Expired entries are already gone,
  # purged before the record was accepted, so the victim is the soonest-expiring
  # entry no connection is claiming. An entry an active connection is claiming is
  # never evicted, so a saturated cache rejects the new admission instead of
  # closing an established peer.
  defp install_live_lease(state, wire, lease) do
    entry = lease_entry(state, wire, lease)

    cond do
      Map.has_key?(state.leases, lease.node_key) ->
        install_admitted_lease(state, lease, entry, nil)

      map_size(state.leases) < state.max_cache_entries ->
        install_admitted_lease(state, lease, entry, nil)

      true ->
        case evictable_lease(state) do
          nil ->
            state =
              log_event(
                %{state | cache_full: state.cache_full + 1},
                :cache_full,
                "gentility admission cache is full and every lease is in use; " <>
                  "rejecting a new admission"
              )

            {:reply, {:error, :cache_full}, state}

          victim ->
            install_admitted_lease(state, lease, entry, victim)
        end
    end
  end

  defp install_admitted_lease(state, lease, entry, victim) do
    state = evict_lease(state, victim)
    node_revision = Budgets.revision(state.budgets, :node, lease.node_key)
    organization_revision = Budgets.revision(state.budgets, :organization, lease.organization_id)

    candidate =
      state
      |> drop_lease_entry(lease.node_key)
      |> put_lease_entry(lease.node_key, entry)
      |> drop_revocation_entry(lease.node_key)

    candidate =
      if revised_budgets?(candidate, lease, node_revision, organization_revision) do
        enforce_revised_budgets(candidate, lease.node_key, lease.organization_id)
      else
        candidate
      end

    state = candidate |> mark_cache_dirty() |> reschedule_timers()
    {:reply, {:ok, context(lease, :live)}, state}
  end

  defp evict_lease(state, nil), do: state

  defp evict_lease(state, victim) do
    state = drop_lease_entry(state, victim)
    close_peer(state, victim, :eviction)

    log_event(
      count_close_peer(state, :eviction),
      :eviction,
      "gentility admission cache is full; evicting the soonest-expiring unclaimed lease"
    )
  end

  # Only a changed allocation can put an established connection over its limit:
  # a claim is refused when it would exceed the limit in force. Scanning claims
  # is therefore confined to the two identities whose revision actually moved.
  defp revised_budgets?(state, lease, node_revision, organization_revision) do
    Budgets.revision(state.budgets, :node, lease.node_key) != node_revision or
      Budgets.revision(state.budgets, :organization, lease.organization_id) !=
        organization_revision
  end

  defp evictable_lease(state) do
    if :gb_trees.is_empty(state.unclaimed) do
      nil
    else
      {{_expires_at_ms, node_key}, _present} = :gb_trees.smallest(state.unclaimed)
      node_key
    end
  end

  # A lease is closed a little before it expires rather than exactly on it, so a
  # region's leases do not all fall due in the same millisecond. The window is
  # taken out of the lease's own lifetime: DERPEX never serves an expired lease.
  defp lease_entry(state, wire, lease) do
    lifetime = max(lease.expires_at_ms - lease.issued_at_ms, 0)
    {numerator, denominator} = @renewal_fraction

    %{
      wire: wire,
      lease: lease,
      close_at_ms: lease.expires_at_ms - state.expiry_jitter.(lifetime),
      renew_at_ms: lease.issued_at_ms + div(lifetime * numerator, denominator)
    }
  end

  defp default_expiry_jitter(lifetime) do
    case div(lifetime * @expiry_jitter_percent, 100) do
      window when window <= 1 -> 0
      window -> :rand.uniform(window) - 1
    end
  end

  defp put_lease_entry(state, node_key, entry) do
    key = expiry_key(node_key, entry)

    state = %{
      state
      | leases: Map.put(state.leases, node_key, entry),
        by_expiry: :gb_trees.enter(key, true, state.by_expiry),
        by_renewal: :gb_trees.enter(renewal_key(node_key, entry), true, state.by_renewal),
        budgets: Budgets.add_lease(state.budgets, entry.lease, now_microsecond(state))
    }

    if claimed?(state, node_key),
      do: state,
      else: %{state | unclaimed: :gb_trees.enter(key, true, state.unclaimed)}
  end

  defp drop_lease_entry(state, node_key) do
    case Map.pop(state.leases, node_key) do
      {nil, _leases} ->
        state

      {entry, leases} ->
        key = expiry_key(node_key, entry)

        %{
          state
          | leases: leases,
            by_expiry: :gb_trees.delete_any(key, state.by_expiry),
            unclaimed: :gb_trees.delete_any(key, state.unclaimed),
            by_renewal: :gb_trees.delete_any(renewal_key(node_key, entry), state.by_renewal),
            budgets: Budgets.remove_lease(state.budgets, entry.lease, now_microsecond(state))
        }
    end
  end

  defp expiry_key(node_key, entry), do: {entry.close_at_ms, node_key}

  defp renewal_key(node_key, entry), do: {entry.renew_at_ms, node_key}

  defp claimed?(state, node_key), do: Map.has_key?(state.node_claims, node_key)

  defp stale_lease?(nil, _lease), do: false

  defp stale_lease?(%{lease: current}, lease) do
    cond do
      current.policy_revision != lease.policy_revision ->
        current.policy_revision > lease.policy_revision

      current.quota_revision != lease.quota_revision ->
        current.quota_revision > lease.quota_revision

      # Same revisions: a reply that expires earlier than what is cached would
      # shorten the lease a connection is already relying on.
      true ->
        current.expires_at_ms > lease.expires_at_ms
    end
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

        state =
          if close? do
            close_peer(state, revocation.node_key, :revocation)
            count_close_peer(state, :revocation)
          else
            state
          end

        state =
          log_event(state, :revocation, "gentility revocation applied; node closed: #{close?}")

        state = persist_now(state) |> reschedule_timers()
        {if(close?, do: :covered, else: :uncovered), state}
    end
  end

  defp apply_reconciliation(state, revocations) do
    {state, applied, stale, close_keys} =
      Enum.reduce(revocations, {state, 0, 0, MapSet.new()}, &reconcile_revocation/2)

    state = close_peers(state, MapSet.to_list(close_keys), :revocation)

    state =
      if applied > 0,
        do:
          log_event(
            state,
            :revocation,
            "gentility reconciliation applied #{applied} revocations, closing " <>
              "#{MapSet.size(close_keys)} nodes"
          ),
        else: state

    state = persist_now(state) |> reschedule_timers()
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

    state = if close?, do: drop_lease_entry(state, revocation.node_key), else: state

    entry = %{
      wire: wire,
      policy_revision: revocation.policy_revision,
      revoked_at_ms: revocation.revoked_at_ms
    }

    {put_revocation_entry(state, revocation.node_key, entry), close?}
  end

  # Revocations are bounded by revocation time: the oldest record is the one
  # Gentility is soonest to prune, and every lease it could still deny has
  # expired by then. The order is indexed so that reaching the bound costs a
  # tree lookup rather than a scan.
  defp put_revocation_entry(state, node_key, entry) do
    state = drop_revocation_entry(state, node_key)

    state = %{
      state
      | revocations: Map.put(state.revocations, node_key, entry),
        revocations_by_time:
          :gb_trees.enter({entry.revoked_at_ms, node_key}, true, state.revocations_by_time)
    }

    if map_size(state.revocations) <= state.max_revocations do
      state
    else
      {{_revoked_at_ms, oldest}, _present} = :gb_trees.smallest(state.revocations_by_time)
      drop_revocation_entry(state, oldest)
    end
  end

  defp drop_revocation_entry(state, node_key) do
    case Map.pop(state.revocations, node_key) do
      {nil, _revocations} ->
        state

      {entry, revocations} ->
        %{
          state
          | revocations: revocations,
            revocations_by_time:
              :gb_trees.delete_any({entry.revoked_at_ms, node_key}, state.revocations_by_time)
        }
    end
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
    with {:ok, lease} <-
           Contract.verify_lease(wire, state.verification_keys, now_ms(state),
             max_lease_ms: state.max_lease_ms,
             max_future_skew_ms: state.max_future_skew_ms
           ),
         :ok <- verify_region(state, lease) do
      {:ok, lease}
    end
  end

  # A lease names the region it was issued for. Serving it anywhere else would
  # let one region's allocation be spent in another, so it is refused wherever
  # a lease is verified: live admission, cache load, renewal, and rotation.
  defp verify_region(%{region_id: nil}, _lease), do: :ok
  defp verify_region(%{region_id: region_id}, %Lease{region_id: region_id}), do: :ok
  defp verify_region(_state, _lease), do: {:error, :wrong_region}

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
        node_budget: Budgets.node_budget(lease),
        organization_budget: Budgets.organization_budget(lease)
      }

      state = %{
        state
        | claims: Map.put(state.claims, connection, claim),
          node_claims: index_claim(state.node_claims, node_key, sequence, connection),
          organization_claims:
            index_claim(state.organization_claims, lease.organization_id, sequence, connection),
          budgets: Budgets.add_claim(state.budgets, claim, now_microsecond(state)),
          sequence: sequence
      }

      {:reply, {:ok, context}, hold_claimed_lease(state, node_key)}
    else
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  # A lease an active connection is claiming leaves the eviction order entirely;
  # it returns to it when the last connection for that node is released.
  defp hold_claimed_lease(state, node_key) do
    case state.leases[node_key] do
      nil ->
        state

      entry ->
        key = expiry_key(node_key, entry)
        %{state | unclaimed: :gb_trees.delete_any(key, state.unclaimed)}
    end
  end

  defp release_claimed_lease(state, node_key) do
    case state.leases[node_key] do
      nil ->
        state

      entry ->
        key = expiry_key(node_key, entry)
        %{state | unclaimed: :gb_trees.enter(key, true, state.unclaimed)}
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
    node_limit = Budgets.connection_limit(state.budgets, :node, lease.node_key)

    organization_limit =
      Budgets.connection_limit(state.budgets, :organization, lease.organization_id)

    node_count = claim_count(state.node_claims, lease.node_key)
    organization_count = claim_count(state.organization_claims, lease.organization_id)

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

        state = %{
          state
          | claims: claims,
            node_claims:
              unindex_claim(state.node_claims, claim.node_key, claim.sequence, connection),
            organization_claims:
              unindex_claim(
                state.organization_claims,
                claim.organization_id,
                claim.sequence,
                connection
              ),
            budgets: Budgets.remove_claim(state.budgets, claim, now_microsecond(state)),
            closing_connections: MapSet.delete(state.closing_connections, connection)
        }

        if claimed?(state, claim.node_key),
          do: state,
          else: release_claimed_lease(state, claim.node_key)
    end
  end

  # Claims are indexed by node and by organization, ordered by claim sequence, so
  # counting an identity's connections and finding its newest ones costs what the
  # answer costs rather than what the census costs.
  defp index_claim(index, identity, sequence, connection) do
    Map.update(
      index,
      identity,
      :gb_sets.singleton({sequence, connection}),
      &:gb_sets.add({sequence, connection}, &1)
    )
  end

  defp unindex_claim(index, identity, sequence, connection) do
    case Map.get(index, identity) do
      nil ->
        index

      claims ->
        claims = :gb_sets.delete_any({sequence, connection}, claims)

        if :gb_sets.is_empty(claims),
          do: Map.delete(index, identity),
          else: Map.put(index, identity, claims)
    end
  end

  defp claim_count(index, identity) do
    case Map.get(index, identity) do
      nil -> 0
      claims -> :gb_sets.size(claims)
    end
  end

  # Only the two identities a revised lease names can have gone over their
  # allocation, so enforcement never walks the whole cache.
  defp enforce_revised_budgets(state, node_key, organization_id) do
    state
    |> over_limit_connections(node_key, organization_id)
    |> Enum.reject(&MapSet.member?(state.closing_connections, &1))
    |> Enum.reduce(state, fn connection, state ->
      state.close_connection.(connection, :quota_revision)
      %{state | closing_connections: MapSet.put(state.closing_connections, connection)}
    end)
  end

  defp over_limit_connections(state, node_key, organization_id) do
    node_excess =
      newest_claims(
        state.node_claims,
        node_key,
        claim_count(state.node_claims, node_key) -
          Budgets.connection_limit(state.budgets, :node, node_key)
      )

    organization_excess =
      newest_claims(
        state.organization_claims,
        organization_id,
        claim_count(state.organization_claims, organization_id) -
          Budgets.connection_limit(state.budgets, :organization, organization_id)
      )

    Enum.uniq(node_excess ++ organization_excess)
  end

  defp newest_claims(index, identity, count) when count > 0 do
    case Map.get(index, identity) do
      nil -> []
      claims -> take_newest(claims, count, [])
    end
  end

  defp newest_claims(_index, _identity, _count), do: []

  defp take_newest(_claims, 0, taken), do: Enum.reverse(taken)

  defp take_newest(claims, count, taken) do
    if :gb_sets.is_empty(claims) do
      Enum.reverse(taken)
    else
      {{_sequence, connection}, claims} = :gb_sets.take_largest(claims)
      take_newest(claims, count - 1, [connection | taken])
    end
  end

  defp load_cache(state) do
    case Cache.load(state.cache_path, state.max_cache_entries, state.max_revocations) do
      {:ok, {lease_wires, revocation_wires}} ->
        load_records(state, lease_wires, revocation_wires)

      {:error, reason} ->
        log_event(
          %{state | load_error: reason},
          :cache_load_error,
          "gentility admission cache could not be loaded: #{inspect(reason)}; " <>
            "starting with no cached leases"
        )
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
    state
    |> drop_lease_entry(lease.node_key)
    |> put_lease_entry(lease.node_key, lease_entry(state, wire, lease))
  end

  # Re-verifying every cached record against a rotated keyring is one Ed25519
  # verification per record, so the sweep runs in bounded chunks between
  # messages. Records still waiting their turn are dropped as the sweep reaches
  # them, which is why a rotation sheds admissions over a brief window instead
  # of atomically.
  defp start_reverify(state) do
    token = make_ref()
    send(self(), {__MODULE__, :reverify, token})

    %{
      state
      | reverify: %{
          token: token,
          leases: Map.keys(state.leases),
          revocations: Map.keys(state.revocations)
        }
    }
  end

  defp reverify_chunk(%{reverify: %{leases: [], revocations: []}} = state) do
    %{state | reverify: nil}
    |> persist_now()
    |> purge_expired()
    |> reschedule_timers()
  end

  defp reverify_chunk(%{reverify: %{leases: []}} = state) do
    {chunk, rest} = Enum.split(state.reverify.revocations, @reverify_chunk)
    state = Enum.reduce(chunk, state, &reverify_revocation/2)
    continue_reverify(put_in(state.reverify.revocations, rest))
  end

  defp reverify_chunk(state) do
    {chunk, rest} = Enum.split(state.reverify.leases, @reverify_chunk)
    {state, closed} = Enum.reduce(chunk, {state, []}, &reverify_lease/2)

    state =
      state
      |> close_peers(closed, :key_rotation)
      |> log_rotation(closed)

    continue_reverify(put_in(state.reverify.leases, rest))
  end

  defp log_rotation(state, []), do: state

  defp log_rotation(state, _closed) do
    log_event(
      state,
      :key_rotation,
      "gentility verification-key rotation is dropping leases signed by a retired key"
    )
  end

  defp continue_reverify(state) do
    send(self(), {__MODULE__, :reverify, state.reverify.token})
    state
  end

  defp reverify_lease(node_key, {state, closed}) do
    case state.leases[node_key] do
      nil ->
        {state, closed}

      entry ->
        case verify_lease(state, entry.wire) do
          {:ok, _lease} -> {state, closed}
          {:error, _retired} -> {drop_lease_entry(state, node_key), [node_key | closed]}
        end
    end
  end

  defp reverify_revocation(node_key, state) do
    case state.revocations[node_key] do
      nil ->
        state

      entry ->
        case Contract.verify_revocation(entry.wire, state.verification_keys) do
          {:ok, _revocation} -> state
          {:error, _retired} -> drop_revocation_entry(state, node_key)
        end
    end
  end

  # Expiry order is maintained incrementally, so purging walks only the leases
  # that have actually expired rather than the whole cache.
  defp purge_expired(state) do
    case purge_expired_leases(state, now_ms(state), []) do
      {state, []} -> state
      {state, keys} -> state |> close_peers(keys, :expiry) |> mark_cache_dirty()
    end
  end

  # The popped key leaves both indexes before anything else happens, so the walk
  # terminates even if an index key ever outlived the entry that created it.
  defp purge_expired_leases(state, now, closed) do
    if :gb_trees.is_empty(state.by_expiry) do
      {state, closed}
    else
      {{expires_at_ms, node_key} = key, _present} = :gb_trees.smallest(state.by_expiry)

      if expires_at_ms <= now do
        state = %{
          state
          | by_expiry: :gb_trees.delete_any(key, state.by_expiry),
            unclaimed: :gb_trees.delete_any(key, state.unclaimed)
        }

        {state, closed} = expire_lease(state, node_key, key, closed)
        purge_expired_leases(state, now, closed)
      else
        {state, closed}
      end
    end
  end

  # An index key that no longer names the cached entry is stale, not an expiry:
  # the lease standing behind that node key expires later and must survive.
  defp expire_lease(state, node_key, key, closed) do
    case state.leases[node_key] do
      nil ->
        {state, closed}

      entry ->
        if expiry_key(node_key, entry) == key do
          {drop_lease_entry(state, node_key), [node_key | closed]}
        else
          {state, closed}
        end
    end
  end

  # Only a lease an established connection is using is worth renewing: an idle
  # cached lease costs nothing to re-authorize on the node's next connection,
  # and renewing the whole cache would put the fleet's reconnection load on
  # Gentility continuously.
  defp renew_due(state) do
    now = now_ms(state)

    if :gb_trees.is_empty(state.by_renewal) do
      state
    else
      {{renew_at_ms, node_key} = key, _present} = :gb_trees.smallest(state.by_renewal)

      if renew_at_ms <= now do
        state = %{state | by_renewal: :gb_trees.delete_any(key, state.by_renewal)}
        renew_due(start_renewal(state, node_key, key))
      else
        state
      end
    end
  end

  defp start_renewal(state, node_key, key) do
    entry = state.leases[node_key]

    cond do
      is_nil(entry) -> state
      renewal_key(node_key, entry) != key -> state
      not claimed?(state, node_key) -> state
      true -> spawn_renewal(state, node_key, entry)
    end
  end

  defp spawn_renewal(state, node_key, entry) do
    case reserve(state.policy.gate, state.policy.max_concurrent_requests) do
      :ok ->
        parent = self()
        authority = state.policy.authority
        timeout = state.policy.authority_timeout
        request = renewal_request(node_key)

        # A renewal is bounded exactly like a live authorization: an authority
        # that never answers is killed at the deadline, so it can neither hold a
        # concurrency slot nor keep a renewal from being retried.
        {pid, monitor} =
          spawn_monitor(fn ->
            result = bounded_authority_answer(authority, request, timeout)
            send(parent, {__MODULE__, :renewed, self(), node_key, result})
          end)

        renewal = %{monitor: monitor, node_key: node_key}
        %{state | renewals: Map.put(state.renewals, pid, renewal)}

      {:error, :admission_overloaded} ->
        requeue_renewal(state, node_key, entry)
    end
  end

  defp bounded_authority_answer(authority, request, timeout) do
    case invoke_with_timeout(authority, request, timeout) do
      {:ok, answer} -> answer
      {:error, _unavailable} = failure -> failure
    end
  end

  # A renewal carries no client info and no source IP: it re-authorizes an
  # identity the relay already holds, and the marker lets an adapter tell it
  # apart from a fresh connection.
  defp renewal_request(node_key) do
    %Request{
      node_key: node_key,
      client_info: nil,
      source_ip: nil,
      mesh_peer?: false,
      metadata: %{renewal: true}
    }
  end

  defp finish_renewal(state, nil), do: release_gate(state)

  defp finish_renewal(state, pid) do
    case Map.pop(state.renewals, pid) do
      {nil, _renewals} ->
        state

      {renewal, renewals} ->
        Process.demonitor(renewal.monitor, [:flush])
        release_gate(%{state | renewals: renewals})
    end
  end

  defp release_gate(state) do
    _remaining = :atomics.sub_get(state.policy.gate, 1, 1)
    state
  end

  defp apply_renewal(state, node_key, {:ok, wire}) when is_binary(wire) do
    case Contract.record_type(wire) do
      {:ok, :lease} -> renew_lease(state, node_key, wire)
      {:ok, :revocation} -> renew_denial(state, node_key, wire)
      {:error, _unknown} -> requeue_renewal_for(state, node_key)
    end
  end

  defp apply_renewal(state, node_key, _failed), do: requeue_renewal_for(state, node_key)

  defp renew_lease(state, node_key, wire) do
    case verify_lease(state, wire) do
      {:ok, %Lease{node_key: ^node_key} = lease} -> install_renewed_lease(state, wire, lease)
      _mismatched_or_invalid -> requeue_renewal_for(state, node_key)
    end
  end

  defp renew_denial(state, node_key, wire) do
    case Contract.verify_revocation(wire, state.verification_keys) do
      {:ok, %Revocation{node_key: ^node_key} = revocation} ->
        {_outcome, state} = revoke_record(state, wire, revocation)
        state

      _mismatched_or_invalid ->
        requeue_renewal_for(state, node_key)
    end
  end

  # A renewal is admission by another name, so it takes the same path: it cannot
  # resurrect a node a revocation has already denied, it cannot roll a revision
  # or an expiry backwards, and it obeys the cache bound. Claims are untouched,
  # so an established connection keeps running across a successful renewal.
  defp install_renewed_lease(state, wire, lease) do
    case accept_verified_lease(state, wire, lease) do
      {:reply, {:ok, _context}, state} -> state
      {:reply, {:error, _denied}, state} -> requeue_renewal_for(state, lease.node_key)
    end
  end

  defp requeue_renewal_for(state, node_key) do
    case state.leases[node_key] do
      nil -> state
      entry -> requeue_renewal(state, node_key, entry)
    end
  end

  # A renewal that could not be attempted or did not succeed is retried while
  # the lease still has life in it; once it does not, the lease simply expires.
  defp requeue_renewal(state, node_key, entry) do
    retry_at_ms = now_ms(state) + state.renewal_retry_ms

    if retry_at_ms < entry.close_at_ms do
      entry = %{entry | renew_at_ms: retry_at_ms}

      %{
        state
        | leases: Map.put(state.leases, node_key, entry),
          by_renewal: :gb_trees.enter(renewal_key(node_key, entry), true, state.by_renewal)
      }
    else
      state
    end
  end

  defp reschedule_timers(state), do: state |> reschedule_expiry() |> reschedule_renewal()

  defp reschedule_renewal(state) do
    state = cancel_renewal(state)

    if :gb_trees.is_empty(state.by_renewal) do
      state
    else
      {{renew_at_ms, _node_key}, _present} = :gb_trees.smallest(state.by_renewal)
      delay = max(renew_at_ms - now_ms(state), 0)
      token = make_ref()
      timer = state.clock.send_after(self(), {__MODULE__, :renew, token}, delay)
      %{state | renewal_timer: timer, renewal_token: token}
    end
  end

  defp cancel_renewal(%{renewal_timer: nil} = state), do: state

  defp cancel_renewal(state) do
    _remaining = state.clock.cancel_timer(state.renewal_timer)
    %{state | renewal_timer: nil, renewal_token: nil}
  end

  defp reschedule_expiry(state) do
    state = cancel_expiry(state)

    if :gb_trees.is_empty(state.by_expiry) do
      state
    else
      {{expires_at_ms, _node_key}, _present} = :gb_trees.smallest(state.by_expiry)
      delay = max(expires_at_ms - now_ms(state), 0)
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

  # A sweep advances one bounded chunk per message, so reclaiming a large table
  # never holds the controller for the length of the table.
  defp step_budget_prune(state, cursor) do
    case Budgets.prune_step(state.budgets, cursor, @budget_prune_chunk) do
      :done ->
        schedule_budget_prune(%{state | budget_prune_cursor: :start})

      {:cont, continuation} ->
        send(self(), {__MODULE__, :prune_budgets_step, state.budget_prune_token})
        %{state | budget_prune_cursor: continuation}
    end
  end

  # Token-bucket rows outlive the lease or claim that created them until this
  # timer reclaims them, so no admission pays for the sweep.
  defp schedule_budget_prune(state) do
    state = cancel_budget_prune(state)
    token = make_ref()

    timer =
      state.clock.send_after(
        self(),
        {__MODULE__, :prune_budgets, token},
        state.budget_prune_ms
      )

    %{state | budget_prune_timer: timer, budget_prune_token: token}
  end

  defp cancel_budget_prune(%{budget_prune_timer: nil} = state), do: state

  defp cancel_budget_prune(state) do
    _remaining = state.clock.cancel_timer(state.budget_prune_timer)
    %{state | budget_prune_timer: nil, budget_prune_token: nil}
  end

  # Lease churn is debounced: a burst of reconnections costs one write, and a
  # crash loses at most `cache_persist_ms` of admissions, which nodes recover by
  # re-authorizing. Revocation is the security-relevant path and is never
  # deferred.
  defp mark_cache_dirty(%{cache_path: nil} = state), do: state

  defp mark_cache_dirty(%{cache_persist_timer: timer} = state) when not is_nil(timer),
    do: %{state | cache_dirty: true}

  defp mark_cache_dirty(state) do
    token = make_ref()

    timer =
      state.clock.send_after(
        self(),
        {__MODULE__, :persist_cache, token},
        state.cache_persist_ms
      )

    %{state | cache_dirty: true, cache_persist_timer: timer, cache_persist_token: token}
  end

  defp persist_now(state), do: state |> Map.put(:cache_dirty, true) |> flush_cache(:sync)

  defp flush_cache(state, mode \\ :async)

  defp flush_cache(%{cache_dirty: false} = state, _mode), do: state

  defp flush_cache(state, mode) do
    state = cancel_cache_persist(state)

    case persist(state, mode) do
      :ok ->
        %{state | cache_dirty: false, persist_error: nil}

      {:error, reason} ->
        state =
          log_event(
            %{state | persist_error: reason},
            :cache_persist_error,
            "gentility admission cache write failed: #{inspect(reason)}"
          )

        mark_cache_dirty(state)
    end
  end

  defp cancel_cache_persist(%{cache_persist_timer: nil} = state), do: state

  defp cancel_cache_persist(state) do
    _remaining = state.clock.cancel_timer(state.cache_persist_timer)
    %{state | cache_persist_timer: nil, cache_persist_token: nil}
  end

  # The snapshot is encoded here so that what reaches disk is one consistent
  # view of controller state; only the write itself leaves the process.
  defp persist(%{cache_writer: nil}, _mode), do: :ok

  defp persist(state, :async), do: CacheWriter.write(state.cache_writer, cache_snapshot(state))

  defp persist(state, :sync) do
    CacheWriter.write_sync(state.cache_writer, cache_snapshot(state), @cache_write_timeout_ms)
  end

  defp cache_snapshot(state) do
    leases =
      state.leases |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(fn {_key, entry} -> entry.wire end)

    revocations =
      state.revocations
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {_key, entry} -> entry.wire end)

    Cache.encode(leases, revocations)
  end

  defp close_peer(state, key, cause) when cause in @close_peer_causes do
    _connection_count = state.close_peer.(key)
    :ok
  end

  # One close is a single router call and stays inline. A batch is handed to the
  # closer so that a reconciliation or an expiry sweep cannot stall admission
  # behind thousands of router calls.
  defp close_peers(state, [], _cause), do: state

  defp close_peers(state, [key], cause) do
    close_peer(state, key, cause)
    count_close_peer(state, cause)
  end

  defp close_peers(state, keys, cause) do
    :ok = Closer.close(state.closer, keys)
    count_close_peer(state, cause, length(keys))
  end

  defp count_close_peer(state, cause, count \\ 1) do
    counts = Map.update(state.close_peer_counts, cause, count, &(&1 + count))
    %{state | close_peer_counts: counts}
  end

  defp unexpected_exit(state, pid, reason) do
    Logger.warning(
      "gentility admission controller ignoring exit from #{inspect(pid)}: #{inspect(reason)}"
    )

    {:noreply, state}
  end

  defp initial_cache_writer(nil), do: {:ok, nil}

  defp initial_cache_writer(path) when is_binary(path) do
    CacheWriter.start_link(path: path, owner: self())
  end

  defp initial_cache_writer(_path), do: {:error, :invalid_cache_path}

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

  defp usage_available(%Policy{usage: nil}), do: :ok

  # Shedding is counted by the connection process itself: a relay that is
  # shedding must not also be paying for a message per shed packet.
  defp usage_available(%Policy{usage: usage} = policy) do
    if :atomics.get(usage.blocked, 1) == 0 do
      :ok
    else
      :atomics.add(policy.counters, @usage_shed_counter, 1)
      {:error, :usage_spool_full}
    end
  end

  # The two shedding outcomes are counted lock-free by the connection process
  # itself, so an overloaded relay does not pay a message to say so.
  defp caller_counts(state, counts) do
    counts
    |> put_caller_count({:denied, :overloaded}, state.policy.counters, @overloaded_counter)
    |> put_caller_count({:denied, :unavailable}, state.policy.counters, @unavailable_counter)
  end

  defp put_caller_count(counts, key, counters, index) do
    case :atomics.get(counters, index) do
      0 -> counts
      value -> Map.update(counts, key, value, &(&1 + value))
    end
  end

  defp nearest_lease_expiry_seconds(state) do
    if :gb_trees.is_empty(state.by_expiry) do
      nil
    else
      {{close_at_ms, _node_key}, _present} = :gb_trees.smallest(state.by_expiry)
      div(max(close_at_ms - now_ms(state), 0), 1_000)
    end
  end

  defp now_ms(state), do: state.clock.system_time(:millisecond)

  defp now_microsecond(state), do: state.clock.monotonic_time(:microsecond)

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

  defp region_option!(options) do
    case Keyword.get(options, :region_id) do
      nil -> nil
      value when is_integer(value) and value in 0..0xFFFF_FFFF -> value
      _invalid -> raise ArgumentError, "region_id must be an unsigned 32-bit integer"
    end
  end

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
