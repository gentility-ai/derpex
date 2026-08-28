defmodule Derpex.Operations do
  @moduledoc """
  Aggregate-only health, consistency, and Prometheus operations surface.

  Public health answers disclose no topology. Detailed consistency and metrics
  require an explicitly configured bearer token.
  """

  alias Derpex.AcceptLimiter
  alias Derpex.Admission.Gentility
  alias Derpex.Admission.Gentility.Events
  alias Derpex.BootstrapDNS
  alias Derpex.Drain
  alias Derpex.HTTP1.Request
  alias Derpex.Metrics
  alias Derpex.Router

  @doc "Checks a request against a configured operations bearer token."
  @spec authorize(Request.t(), keyword()) :: :authorized | :disabled | :unauthorized
  def authorize(_request, options) when not is_list(options), do: :disabled

  def authorize(request, options) do
    if Keyword.get(options, :enabled, false) do
      authorize_enabled(request, Keyword.get(options, :token))
    else
      :disabled
    end
  end

  @doc false
  @spec enabled?(keyword()) :: boolean()
  def enabled?(options), do: is_list(options) and Keyword.get(options, :enabled, false)

  defp authorize_enabled(request, token) do
    case token do
      token when is_binary(token) and byte_size(token) >= 16 ->
        expected = "Bearer " <> token
        provided = Request.header(request, "authorization")

        if is_binary(provided) and byte_size(provided) == byte_size(expected) and
             :crypto.hash_equals(provided, expected),
           do: :authorized,
           else: :unauthorized

      _missing_or_short ->
        :disabled
    end
  end

  @doc "Returns liveness or readiness without attributed details."
  @spec health(:live | :ready) :: :ok | {:error, :unhealthy | :not_ready}
  def health(:live) do
    required = [Metrics, Router, AcceptLimiter, Drain]

    if Enum.all?(required, &alive?/1) do
      :ok
    else
      {:error, :unhealthy}
    end
  end

  def health(:ready) do
    with :ok <- health(:live),
         {:ok, %{accepting_home?: true}} <- safe(&Drain.stats/0),
         :ok <- gentility_ready() do
      :ok
    else
      _unready -> {:error, :not_ready}
    end
  end

  @doc "Runs internal topology checks without returning client identities."
  @spec consistency_check() :: :ok | {:error, binary()}
  def consistency_check do
    case safe(&Router.consistency_check/0) do
      {:ok, :ok} -> :ok
      {:ok, {:error, reason}} -> {:error, reason}
      {:error, _reason} -> {:error, "router consistency check unavailable"}
    end
  end

  @doc "Renders deterministic Prometheus text with fixed names and no labels."
  @spec prometheus() :: binary()
  def prometheus do
    metrics =
      %{}
      |> merge_core_metrics()
      |> merge_router_metrics()
      |> merge_accept_metrics()
      |> merge_drain_metrics()
      |> merge_bootstrap_metrics()
      |> merge_gentility_metrics()
      |> merge_event_metrics()
      |> merge_vm_metrics()

    metrics
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map_join(fn {name, value} -> "#{name} #{numeric(value)}\n" end)
  end

  defp gentility_ready do
    case Process.whereis(Gentility) do
      nil ->
        missing_gentility_result()

      _pid ->
        Gentility
        |> Gentility.stats()
        |> usage_ready()
    end
  rescue
    _exception -> {:error, :unavailable}
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  defp missing_gentility_result do
    if Application.get_env(:derpex, :gentility), do: {:error, :missing}, else: :ok
  end

  defp usage_ready(%{usage: %{blocked?: true}}), do: {:error, :usage_blocked}
  defp usage_ready(_stats), do: :ok

  defp merge_core_metrics(metrics) do
    case safe(&Metrics.snapshot/0) do
      {:ok, counters} ->
        Enum.reduce(counters, metrics, fn {name, value}, metrics ->
          Map.put(metrics, core_metric_name(name), value)
        end)

      {:error, _reason} ->
        metrics
    end
  end

  defp merge_router_metrics(metrics) do
    names = %{
      current_connections: "derp_gauge_current_connections",
      current_not_ideal_connections: "derp_gauge_current_notideal_connections",
      clients_total: "derp_gauge_clients_total",
      clients_local: "derp_gauge_clients_local",
      clients_remote: "derp_gauge_clients_remote",
      current_duplicate_client_keys: "derp_gauge_current_dup_client_keys",
      current_duplicate_connections: "derp_gauge_current_dup_client_conns",
      watchers: "derp_gauge_watchers",
      forwarder_keys: "derpex_forwarder_keys",
      forwarder_paths: "derpex_forwarder_paths"
    }

    merge_named_snapshot(metrics, safe(&Router.stats/0), names)
  end

  defp merge_accept_metrics(metrics) do
    names = %{
      allowed: "derpex_accept_allowed_total",
      accept_rate_limited: "derpex_accept_global_rate_limited_total",
      ip_rate_limited: "derpex_accept_ip_rate_limited_total",
      ip_connection_limited: "derpex_accept_ip_connection_limited_total",
      ip_tracking_limited: "derpex_accept_ip_tracking_limited_total",
      tracked_ips: "derpex_accept_tracked_ips",
      active_connections: "derpex_accept_active_connections",
      max_tracked_ips: "derpex_accept_max_tracked_ips"
    }

    merge_named_snapshot(metrics, safe(&AcceptLimiter.stats/0), names)
  end

  defp merge_drain_metrics(metrics) do
    names = %{
      draining?: "derpex_drain_active",
      accepting_home?: "derpex_drain_accepting_home",
      connections: "derpex_drain_connections",
      home_connections: "derp_gauge_current_home_connections",
      targeted_connections: "derpex_drain_targeted_connections",
      deadline_remaining_ms: "derpex_drain_deadline_remaining_ms",
      notifications_enqueued: "derpex_drain_notifications_total",
      notification_drops: "derpex_drain_notification_drops_total",
      deadline_closes: "derpex_drain_deadline_closes_total"
    }

    merge_named_snapshot(metrics, safe(&Drain.stats/0), names)
  end

  defp merge_bootstrap_metrics(metrics) do
    names = %{
      requests: "counter_bootstrap_dns_requests",
      published_hits: "counter_bootstrap_dns_published_hits",
      published_misses: "counter_bootstrap_dns_published_misses",
      unpublished_hits: "counter_bootstrap_dns_unpublished_hits",
      unpublished_misses: "counter_bootstrap_dns_unpublished_misses",
      unpublished_percent_misses: "counter_bootstrap_dns_unpublished_percent_misses",
      queried_domains: "counter_bootstrap_dns_queried_domains"
    }

    merge_named_snapshot(metrics, safe(&BootstrapDNS.metrics/0), names)
  end

  defp merge_gentility_metrics(metrics) do
    case Process.whereis(Gentility) do
      nil ->
        metrics

      _pid ->
        merge_live_gentility(metrics)
    end
  end

  defp merge_live_gentility(metrics) do
    case safe(fn -> Gentility.stats(Gentility) end) do
      {:ok, values} -> merge_gentility_snapshot(metrics, values)
      _unavailable -> metrics
    end
  end

  defp merge_usage_metrics(metrics, usage) do
    names = %{
      enabled: "derpex_gentility_usage_enabled",
      spool_batches: "derpex_gentility_usage_spool_batches",
      spool_bytes: "derpex_gentility_usage_spool_bytes",
      aggregate_entries: "derpex_gentility_usage_aggregate_entries",
      aggregate_windows: "derpex_gentility_usage_aggregate_windows",
      blocked?: "derpex_gentility_usage_blocked",
      exporting?: "derpex_gentility_usage_exporting"
    }

    merge_values(metrics, usage, names)
  end

  defp merge_gentility_snapshot(metrics, %{usage: usage} = values) do
    names = %{
      cache_entries: "derpex_gentility_cache_entries",
      revocations: "derpex_gentility_revocations",
      active_connections: "derpex_gentility_active_connections",
      active_nodes: "derpex_gentility_active_nodes",
      active_organizations: "derpex_gentility_active_organizations",
      active_requests: "derpex_gentility_active_requests",
      max_cache_entries: "derpex_gentility_max_cache_entries",
      max_revocations: "derpex_gentility_max_revocations"
    }

    metrics
    |> merge_values(values, names)
    |> merge_usage_metrics(usage)
  end

  defp merge_event_metrics(metrics) do
    case Process.whereis(Events) do
      nil ->
        metrics

      _pid ->
        names = %{
          connected?: "derpex_gentility_events_connected",
          reconciling?: "derpex_gentility_events_reconciling",
          retrying?: "derpex_gentility_events_retrying",
          reconciliations: "derpex_gentility_events_reconciliations_total",
          revocations: "derpex_gentility_events_revocations_total"
        }

        merge_named_snapshot(metrics, safe(fn -> Events.stats(Events) end), names)
    end
  end

  defp merge_vm_metrics(metrics) do
    metrics
    |> Map.put("derpex_vm_memory_bytes", :erlang.memory(:total))
    |> Map.put("derpex_vm_process_count", :erlang.system_info(:process_count))
    |> Map.put("derpex_vm_process_limit", :erlang.system_info(:process_limit))
    |> Map.put("derpex_vm_run_queue", :erlang.statistics(:run_queue))
  end

  defp merge_named_snapshot(metrics, {:ok, values}, names),
    do: merge_values(metrics, values, names)

  defp merge_named_snapshot(metrics, {:error, _reason}, _names), do: metrics

  defp merge_values(metrics, values, names) do
    Enum.reduce(names, metrics, fn {key, name}, metrics ->
      case Map.get(values, key) do
        value when is_integer(value) or is_float(value) or is_boolean(value) ->
          Map.put(metrics, name, value)

        nil ->
          metrics

        _non_numeric ->
          metrics
      end
    end)
  end

  defp numeric(true), do: 1
  defp numeric(false), do: 0
  defp numeric(value), do: value

  defp core_metric_name(:packets_received_disco),
    do: ~s(derp_counter_packets_received_kind{kind="disco"})

  defp core_metric_name(:packets_received_other),
    do: ~s(derp_counter_packets_received_kind{kind="other"})

  defp core_metric_name({metric, reason, kind})
       when metric in [:packets_dropped, :bytes_dropped] do
    ~s(derp_#{metric}{kind="#{kind}",reason="#{reason}"})
  end

  defp core_metric_name(name), do: "derp_#{name}"

  defp alive?(name) do
    case Process.whereis(name) do
      pid when is_pid(pid) -> Process.alive?(pid)
      nil -> false
    end
  end

  defp safe(function) do
    {:ok, function.()}
  rescue
    _exception -> {:error, :unavailable}
  catch
    :exit, _reason -> {:error, :unavailable}
  end
end
