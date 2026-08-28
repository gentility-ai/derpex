defmodule Derpex.MetricsTest do
  use ExUnit.Case, async: false

  alias Derpex.Metrics

  test "updates fixed counters directly and exposes every stable name" do
    handle = Metrics.default_handle()
    before = Metrics.snapshot()

    assert :ok = Metrics.add(handle, :packets_received, 2)
    assert :ok = Metrics.add(handle, :bytes_received, 128)

    after_snapshot = Metrics.snapshot()
    assert after_snapshot.packets_received == before.packets_received + 2
    assert after_snapshot.bytes_received == before.bytes_received + 128
    assert Map.keys(after_snapshot) |> Enum.sort() == Metrics.metric_names() |> Enum.sort()
    assert Enum.all?(after_snapshot, fn {_name, value} -> value >= 0 end)
  end
end
