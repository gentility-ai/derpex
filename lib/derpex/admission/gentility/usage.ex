defmodule Derpex.Admission.Gentility.Usage do
  @moduledoc false

  alias Derpex.Admission.Gentility.UsageBatch
  alias Derpex.Admission.Gentility.UsageBatch.Entry

  @type outcome :: :accepted | :dropped

  @doc "Creates fixed-window aggregate storage owned by the usage worker."
  @spec new() :: :ets.tid()
  def new do
    :ets.new(__MODULE__, [
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: :auto,
      decentralized_counters: true
    ])
  end

  @doc "Records one sender-attributed relay outcome without a process hop."
  @spec record(:ets.tid(), pos_integer(), map(), non_neg_integer(), outcome(), integer()) ::
          :ok | {:error, term()}
  def record(table, window_ms, gentility, bytes, outcome, now_ms)
      when is_integer(bytes) and bytes >= 0 and outcome in [:accepted, :dropped] do
    window_start = div(now_ms, window_ms) * window_ms

    key =
      {window_start, gentility.node_id, gentility.organization_id, gentility.owner_kind,
       gentility.deployment_id}

    increments = increments(outcome, bytes)
    _counters = :ets.update_counter(table, key, increments, {key, 0, 0, 0, 0})
    :ok
  rescue
    ArgumentError -> {:error, :usage_unavailable}
  end

  @doc """
  Snapshots every row of the oldest complete window without deleting them.

  Rows come back in canonical entry order, so the caller sorts a window once
  and then splits it into as many batches as the contract needs.
  """
  @spec oldest_closed(:ets.tid(), pos_integer(), integer()) ::
          nil | {non_neg_integer(), [tuple()]}
  def oldest_closed(table, window_ms, now_ms) do
    current_window = div(now_ms, window_ms) * window_ms

    case oldest_window(table, current_window) do
      nil ->
        nil

      window_start ->
        rows =
          table
          |> :ets.match_object({{window_start, :_, :_, :_, :_}, :_, :_, :_, :_})
          |> Enum.sort_by(&row_identity/1)

        {window_start, rows}
    end
  rescue
    ArgumentError -> nil
  end

  @doc "Builds the contract batch covering one already-ordered slice of a window."
  @spec batch(binary(), non_neg_integer(), non_neg_integer(), pos_integer(), [tuple()]) ::
          UsageBatch.t()
  def batch(instance_id, region_id, window_start_ms, window_ms, rows) do
    %UsageBatch{
      instance_id: instance_id,
      region_id: region_id,
      window_start_ms: window_start_ms,
      window_end_ms: window_start_ms + window_ms,
      entries: Enum.map(rows, &entry/1)
    }
  end

  @doc "Subtracts precisely the counters durably committed to a batch."
  @spec delete_rows(:ets.tid(), [tuple()]) :: :ok
  def delete_rows(table, rows) do
    Enum.each(rows, fn {key, accepted_packets, accepted_bytes, dropped_packets, dropped_bytes} ->
      remaining =
        :ets.update_counter(table, key, [
          {2, -accepted_packets},
          {3, -accepted_bytes},
          {4, -dropped_packets},
          {5, -dropped_bytes}
        ])

      if remaining == [0, 0, 0, 0], do: :ets.delete_object(table, {key, 0, 0, 0, 0})
    end)

    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc "Returns bounded aggregate-table dimensions."
  @spec stats(:ets.tid()) :: %{entries: non_neg_integer(), windows: non_neg_integer()}
  def stats(table) do
    rows = :ets.tab2list(table)

    windows =
      rows
      |> Enum.map(fn {{window, _, _, _, _}, _, _, _, _} -> window end)
      |> Enum.uniq()

    %{entries: length(rows), windows: length(windows)}
  rescue
    ArgumentError -> %{entries: 0, windows: 0}
  end

  # Must stay identical to `UsageContract`'s `entry_identity/1` ordering: rows are
  # sorted here once so that every batch cut from a window is already in the
  # canonical order the contract encodes, and a chunk boundary is stable.
  defp row_identity(
         {{_window, node_id, organization_id, owner_kind, deployment_id}, _ap, _ab, _dp, _db}
       ) do
    {organization_id, node_id, owner_kind, deployment_id}
  end

  defp increments(:accepted, bytes), do: [{2, 1}, {3, bytes}]
  defp increments(:dropped, bytes), do: [{4, 1}, {5, bytes}]

  defp oldest_window(table, current_window) do
    match = [
      {{{:"$1", :_, :_, :_, :_}, :_, :_, :_, :_}, [{:<, :"$1", current_window}], [:"$1"]}
    ]

    table
    |> :ets.select(match)
    |> Enum.min(fn -> nil end)
  end

  defp entry(
         {{_window, node_id, organization_id, owner_kind, deployment_id}, accepted_packets,
          accepted_bytes, dropped_packets, dropped_bytes}
       ) do
    %Entry{
      node_id: node_id,
      organization_id: organization_id,
      owner_kind: owner_kind,
      deployment_id: deployment_id,
      accepted_packets: accepted_packets,
      accepted_bytes: accepted_bytes,
      dropped_packets: dropped_packets,
      dropped_bytes: dropped_bytes
    }
  end
end
