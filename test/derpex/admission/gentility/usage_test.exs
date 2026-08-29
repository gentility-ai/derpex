defmodule Derpex.Admission.Gentility.UsageTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.Usage

  test "aggregates outcomes by fixed window and sender attribution" do
    table = Usage.new()
    context = context("node-a")
    assert Usage.record(table, 1_000, context, 100, :accepted, 1_100) == :ok
    assert Usage.record(table, 1_000, context, 20, :dropped, 1_999) == :ok
    assert Usage.record(table, 1_000, context("node-b"), 50, :accepted, 2_000) == :ok

    assert {batch, rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000)
    assert batch.window_start_ms == 1_000
    assert batch.window_end_ms == 2_000
    assert batch.instance_id == "derpex-1"
    assert batch.region_id == 17

    assert [entry] = batch.entries
    assert entry.node_id == "node-a"
    assert entry.accepted_packets == 1
    assert entry.accepted_bytes == 100
    assert entry.dropped_packets == 1
    assert entry.dropped_bytes == 20

    assert Usage.delete_rows(table, rows) == :ok
    assert Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000) == nil
    assert Usage.stats(table) == %{entries: 1, windows: 1}
  end

  test "chunks a window into batches of at most the requested entry count" do
    table = Usage.new()

    for index <- 1..5 do
      assert Usage.record(table, 1_000, context("node-#{index}"), 10, :accepted, 1_500) == :ok
    end

    assert {batch, rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000, 2)
    assert length(batch.entries) == 2
    assert length(rows) == 2
    assert Usage.delete_rows(table, rows) == :ok

    assert {second, second_rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000, 2)
    assert length(second.entries) == 2
    assert second.window_start_ms == batch.window_start_ms
    assert Usage.delete_rows(table, second_rows) == :ok

    assert {last, last_rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000, 2)
    assert length(last.entries) == 1
    assert Usage.delete_rows(table, last_rows) == :ok
    assert Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000, 2) == nil

    identities =
      [batch, second, last]
      |> Enum.flat_map(& &1.entries)
      |> Enum.map(& &1.node_id)
      |> Enum.sort()

    assert identities == Enum.sort(Enum.map(1..5, &"node-#{&1}"))
  end

  test "concurrent packet-path updates do not lose counters" do
    table = Usage.new()
    context = context("node-a")

    1..1_000
    |> Task.async_stream(
      fn _index -> Usage.record(table, 1_000, context, 64, :accepted, 1_500) end,
      max_concurrency: 100,
      ordered: false
    )
    |> Stream.run()

    assert {batch, _rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000)
    assert [entry] = batch.entries
    assert entry.accepted_packets == 1_000
    assert entry.accepted_bytes == 64_000
  end

  test "committing a snapshot preserves counters added while it is being persisted" do
    table = Usage.new()
    context = context("node-a")
    assert Usage.record(table, 1_000, context, 100, :accepted, 1_500) == :ok
    assert {_batch, rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000)

    assert Usage.record(table, 1_000, context, 25, :accepted, 1_500) == :ok
    assert Usage.delete_rows(table, rows) == :ok

    assert {batch, _rows} = Usage.oldest_closed(table, 1_000, "derpex-1", 17, 2_000)
    assert [entry] = batch.entries
    assert entry.accepted_packets == 1
    assert entry.accepted_bytes == 25
  end

  defp context(node_id) do
    %{
      node_id: node_id,
      organization_id: "org-1",
      owner_kind: "deployment",
      deployment_id: "dep-1"
    }
  end
end
