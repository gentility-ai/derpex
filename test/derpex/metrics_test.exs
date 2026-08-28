defmodule Derpex.MetricsTest do
  use ExUnit.Case, async: false

  alias Derpex.Metrics
  alias Derpex.Outbox.Ring

  test "updates fixed counters directly and exposes every stable name" do
    handle = Metrics.default_handle()
    before = Metrics.snapshot()

    assert :ok = Metrics.add(handle, :packets_received, 2)
    assert :ok = Metrics.add(handle, :bytes_received, 128)
    assert :ok = Metrics.observe_queue_duration(handle, 2_000_000)

    after_snapshot = Metrics.snapshot()
    assert after_snapshot.packets_received == before.packets_received + 2
    assert after_snapshot.bytes_received == before.bytes_received + 128
    assert Map.keys(after_snapshot) |> Enum.sort() == Metrics.metric_names() |> Enum.sort()
    assert Enum.all?(after_snapshot, fn {_name, value} -> value >= 0 end)

    assert_in_delta after_snapshot.average_queue_duration_ms,
                    0.9 * before.average_queue_duration_ms + 200.0,
                    0.000_001
  end

  test "retains queue replacement and disconnect drops after a ring is destroyed" do
    handle = Metrics.default_handle()
    before = Metrics.snapshot()
    ring = Ring.new(1, metrics: handle, metric_kind: :other)
    source = :binary.copy(<<1>>, 32)

    assert Ring.enqueue(ring, {:recv_packet, source, :binary.copy(<<2>>, 10)}) == {:ok, :wake}

    assert Ring.enqueue(ring, {:recv_packet, source, :binary.copy(<<3>>, 7)}) ==
             {:ok, :replaced}

    assert Ring.close(ring) == :ok
    assert Ring.enqueue(ring, {:recv_packet, source, "bye"}) == {:dropped, :closed}

    after_snapshot = Metrics.snapshot()

    assert delta(after_snapshot, before, {:packets_dropped, :queue_head, :other}) == 1
    assert delta(after_snapshot, before, {:bytes_dropped, :queue_head, :other}) == 10
    assert delta(after_snapshot, before, {:packets_dropped, :gone_disconnected, :other}) == 2
    assert delta(after_snapshot, before, {:bytes_dropped, :gone_disconnected, :other}) == 10
  end

  defp delta(after_snapshot, before, key), do: after_snapshot[key] - before[key]
end
