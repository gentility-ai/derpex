defmodule Derpex.Admission.Gentility.ByteBudgetTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.ByteBudget

  test "paces aggregate reservations without a controller-process hop" do
    table = ByteBudget.new()
    budget = budget(1, 100, 100)
    assert ByteBudget.sync(table, :node, budget, 0) == :ok

    assert ByteBudget.reserve(table, :node, "node-1", 100, 0) == {:ok, 0}
    assert ByteBudget.reserve(table, :node, "node-1", 50, 0) == {:ok, 500_000}
    assert ByteBudget.reserve(table, :node, "node-1", 50, 500_000) == {:ok, 500_000}

    assert ByteBudget.reserve(table, :node, "node-1", 101, 500_000) ==
             {:error, :exceeds_byte_burst}
  end

  test "a newer revision preserves consumption while old revisions cannot roll it back" do
    table = ByteBudget.new()
    assert ByteBudget.sync(table, :node, budget(2, 100, 100), 0) == :ok
    assert ByteBudget.reserve(table, :node, "node-1", 100, 0) == {:ok, 0}

    assert ByteBudget.sync(table, :node, budget(1, 10_000, 10_000), 500_000) == :ok
    assert ByteBudget.reserve(table, :node, "node-1", 50, 500_000) == {:ok, 0}

    assert ByteBudget.sync(table, :node, budget(3, 200, 200), 500_000) == :ok
    assert ByteBudget.reserve(table, :node, "node-1", 100, 500_000) == {:ok, 500_000}
  end

  test "compare-and-swap reservations serialize concurrent consumers" do
    table = ByteBudget.new()
    assert ByteBudget.sync(table, :organization, budget(1, 1_000, 10), 0) == :ok

    delays =
      1..100
      |> Task.async_stream(
        fn _index -> ByteBudget.reserve(table, :organization, "node-1", 1, 0) end,
        max_concurrency: 100,
        ordered: false
      )
      |> Enum.map(fn {:ok, {:ok, delay}} -> delay end)
      |> Enum.sort()

    assert Enum.take(delays, 10) == List.duplicate(0, 10)
    assert Enum.at(delays, 10) == 1_000
    assert List.last(delays) == 90_000
  end

  test "zero rate is unlimited and pruning removes retired identities" do
    table = ByteBudget.new()
    assert ByteBudget.sync(table, :node, budget(1, 0, 0), 0) == :ok
    assert ByteBudget.reserve(table, :node, "node-1", 1_000_000, 0) == {:ok, 0}
    assert ByteBudget.prune(table, MapSet.new()) == :ok

    assert ByteBudget.reserve(table, :node, "node-1", 1, 0) ==
             {:error, :byte_budget_missing}
  end

  defp budget(revision, rate, burst) do
    %{
      identity: "node-1",
      revision: revision,
      bytes_per_second: rate,
      byte_burst: burst
    }
  end
end
