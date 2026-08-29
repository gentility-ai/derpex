defmodule Derpex.Admission.Gentility.UsageTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.Usage

  test "aggregates outcomes by fixed window and sender attribution" do
    table = Usage.new()
    context = context("node-a")
    assert Usage.record(table, 1_000, context, 100, :accepted, 1_100) == :ok
    assert Usage.record(table, 1_000, context, 20, :dropped, 1_999) == :ok
    assert Usage.record(table, 1_000, context("node-b"), 50, :accepted, 2_000) == :ok

    assert {1_000, rows} = Usage.oldest_closed(table, 1_000, 2_000)
    batch = Usage.batch("derpex-1", 17, 1_000, 1_000, rows)
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
    assert Usage.oldest_closed(table, 1_000, 2_000) == nil
    assert Usage.stats(table) == %{entries: 1, windows: 1}
  end

  test "orders a whole window once so it can be cut into batches" do
    table = Usage.new()

    for index <- 1..5 do
      assert Usage.record(table, 1_000, context("node-#{index}"), 10, :accepted, 1_500) == :ok
    end

    assert {1_000, rows} = Usage.oldest_closed(table, 1_000, 2_000)
    assert length(rows) == 5

    identities =
      rows
      |> Enum.map(fn {{_window, node_id, organization_id, owner_kind, deployment_id}, _ap, _ab,
                      _dp, _db} ->
        {organization_id, node_id, owner_kind, deployment_id}
      end)

    assert identities == Enum.sort(identities)

    {chunk, rest} = Enum.split(rows, 2)
    batch = Usage.batch("derpex-1", 17, 1_000, 1_000, chunk)
    assert length(batch.entries) == 2
    assert Enum.map(batch.entries, & &1.node_id) == ["node-1", "node-2"]

    assert Usage.delete_rows(table, chunk) == :ok
    assert {1_000, remaining} = Usage.oldest_closed(table, 1_000, 2_000)
    assert length(remaining) == 3
    assert Usage.delete_rows(table, rest) == :ok
    assert Usage.oldest_closed(table, 1_000, 2_000) == nil
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

    assert {1_000, rows} = Usage.oldest_closed(table, 1_000, 2_000)
    assert [entry] = Usage.batch("derpex-1", 17, 1_000, 1_000, rows).entries
    assert entry.accepted_packets == 1_000
    assert entry.accepted_bytes == 64_000
  end

  test "committing a snapshot preserves counters added while it is being persisted" do
    table = Usage.new()
    context = context("node-a")
    assert Usage.record(table, 1_000, context, 100, :accepted, 1_500) == :ok
    assert {1_000, rows} = Usage.oldest_closed(table, 1_000, 2_000)

    assert Usage.record(table, 1_000, context, 25, :accepted, 1_500) == :ok
    assert Usage.delete_rows(table, rows) == :ok

    assert {1_000, remaining} = Usage.oldest_closed(table, 1_000, 2_000)
    assert [entry] = Usage.batch("derpex-1", 17, 1_000, 1_000, remaining).entries
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
