defmodule Derpex.Admission.Gentility.Usage do
  @moduledoc false

  alias Derpex.Admission.Gentility.UsageBatch
  alias Derpex.Admission.Gentility.UsageBatch.Entry

  @type outcome :: :accepted | :dropped

  @doc "Creates fixed-window aggregate storage owned by the admission controller."
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

  @doc "Snapshots the oldest complete window without deleting it."
  @spec oldest_closed(:ets.tid(), pos_integer(), binary(), non_neg_integer(), integer()) ::
          nil | {UsageBatch.t(), [tuple()]}
  def oldest_closed(table, window_ms, instance_id, region_id, now_ms) do
    current_window = div(now_ms, window_ms) * window_ms

    case oldest_window(table, current_window) do
      nil ->
        nil

      window_start ->
        rows = :ets.match_object(table, {{window_start, :_, :_, :_, :_}, :_, :_, :_, :_})

        batch = %UsageBatch{
          instance_id: instance_id,
          region_id: region_id,
          window_start_ms: window_start,
          window_end_ms: window_start + window_ms,
          entries: Enum.map(rows, &entry/1)
        }

        {batch, rows}
    end
  rescue
    ArgumentError -> nil
  end

  @doc "Deletes precisely the rows that were durably committed to a batch."
  @spec delete_rows(:ets.tid(), [tuple()]) :: :ok
  def delete_rows(table, rows) do
    Enum.each(rows, &:ets.delete_object(table, &1))
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
