defmodule Derpex.Outbox.RingTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Ring

  @enqueue_results [{:ok, :wake}, {:ok, :coalesced}, {:ok, :replaced}, {:dropped, :contention}]

  test "coalesces wakeups and replaces the oldest item at fixed capacity" do
    ring = Ring.new(2, wake_message: :ready)

    assert Ring.enqueue(ring, :first) == {:ok, :wake}
    assert_receive :ready
    assert Ring.enqueue(ring, :second) == {:ok, :coalesced}
    assert Ring.enqueue(ring, :third) == {:ok, :replaced}
    refute_receive :ready

    assert Ring.stats(ring) == %{
             capacity: 2,
             size: 2,
             wake_pending: true,
             head_drops: 1,
             tail_drops: 0,
             closed: false,
             packet_slots: 2
           }

    assert Ring.take(ring) == {:ok, :second}
    assert Ring.take(ring) == {:ok, :third}
    assert Ring.take(ring) == :empty
    assert Ring.enqueue(ring, :fourth) == {:ok, :wake}
    assert_receive :ready
  end

  test "a stalled writer receives no packet-bearing mailbox messages" do
    ring = Ring.new(32, wake_message: :ready)
    assert Ring.enqueue(ring, {:packet, 1}) == {:ok, :wake}
    assert_receive :ready

    for sequence <- 2..10_000 do
      assert Ring.enqueue(ring, {:packet, sequence}) in [{:ok, :coalesced}, {:ok, :replaced}]
    end

    assert {:messages, []} = Process.info(self(), :messages)
    stats = Ring.stats(ring)
    assert stats.size == 32
    assert stats.packet_slots == 32
    assert stats.head_drops == 10_000 - 32

    assert Ring.take(ring) == {:ok, {:packet, 9_969}}
  end

  test "a held lock makes every producer attempt an immediate counted tail drop" do
    parent = self()
    ring = Ring.new(1, wake_message: :ready, test_hook: holding_hook(parent))
    {holder, holder_monitor} = spawn_monitor(fn -> Ring.enqueue(ring, :first) end)
    assert_receive {:holding, ^holder}

    assert Ring.enqueue(ring, :second) == {:dropped, :contention}

    # A producer that waited on the lock would need at least one millisecond per
    # attempt; a single attempt costs microseconds even when the lock is held.
    attempts = 1_000

    {contender, contender_monitor} =
      spawn_monitor(fn -> send(parent, contend_many(ring, attempts)) end)

    assert_receive {elapsed_microseconds, results}
    assert_receive {:DOWN, ^contender_monitor, :process, ^contender, :normal}
    assert results == %{{:dropped, :contention} => attempts}
    assert elapsed_microseconds < 500_000

    send(holder, :release)
    assert_receive {:DOWN, ^holder_monitor, :process, ^holder, :normal}
    assert_receive :ready
    assert Ring.take(ring) == {:ok, :first}
    assert Ring.stats(ring).tail_drops == attempts + 1
  end

  # Saturating fan-in is the worst case for a single-attempt lock: most attempts
  # of eight producers that never pause land on a held lock and become counted
  # tail drops. What must hold is that nothing is lost silently and no producer
  # ever waits for the writer.
  test "concurrent producers never wait and every item is delivered or counted" do
    parent = self()
    producer_count = 8
    per_producer = 500
    sent = producer_count * per_producer
    consumer = spawn_link(&await_ring/0)
    ring = Ring.new(32, notifier: consumer, wake_message: :ready)
    send(consumer, {:ring, ring})

    producers =
      Enum.map(1..producer_count, fn index ->
        spawn_monitor(fn ->
          send(parent, {:produced, self(), contend_many(ring, per_producer, index)})
        end)
      end)

    outcomes =
      Enum.map(producers, fn {producer, monitor} ->
        assert_receive {:produced, ^producer, outcome}, 5_000
        assert_receive {:DOWN, ^monitor, :process, ^producer, :normal}, 5_000
        outcome
      end)

    send(consumer, {:stop, self()})
    assert_receive {:consumed, delivered}, 5_000
    stats = Ring.stats(ring)

    results =
      Enum.reduce(outcomes, %{}, fn {_elapsed, counts}, tally ->
        Map.merge(tally, counts, fn _result, left, right -> left + right end)
      end)

    assert Map.keys(results) -- @enqueue_results == []
    assert Map.get(results, {:dropped, :contention}, 0) == stats.tail_drops
    assert delivered + stats.head_drops + stats.tail_drops == sent
    assert delivered > 0
  end

  test "a producer killed while contending never wedges the consumer" do
    parent = self()
    ring = Ring.new(4, wake_message: :ready, test_hook: holding_hook(parent))
    {holder, holder_monitor} = spawn_monitor(fn -> Ring.enqueue(ring, :held) end)

    assert_receive :ready
    assert_receive {:holding, ^holder}

    Enum.each(1..5, fn _attempt ->
      {producer, producer_monitor} = spawn_monitor(fn -> contend(ring, parent) end)
      assert_receive {:contending, ^producer}
      Process.exit(producer, :kill)
      assert_receive {:DOWN, ^producer_monitor, :process, ^producer, :killed}
    end)

    send(holder, :release)
    assert_receive {:DOWN, ^holder_monitor, :process, ^holder, :normal}

    assert Ring.take(ring) == {:ok, :held}
  end

  test "recovers a producer killed before or after slot publication" do
    assert_stale_producer_recovery(:after_journal, :empty)
    assert_stale_producer_recovery(:after_publish, {:ok, :packet})
  end

  test "close is idempotent and clears every retained reference" do
    ring = Ring.new(2)
    assert Ring.enqueue(ring, :first) == {:ok, :wake}
    assert Ring.enqueue(ring, :second) == {:ok, :coalesced}

    assert Ring.close(ring) == :ok
    assert Ring.close(ring) == :ok
    assert Ring.take(ring) == :closed
    assert Ring.enqueue(ring, :third) == {:dropped, :closed}
    assert Ring.stats(ring).packet_slots == 0
  end

  defp assert_stale_producer_recovery(stop_phase, expected) do
    parent = self()

    hook = fn phase ->
      if phase == stop_phase and self() != parent do
        send(parent, {:stopped, self()})

        receive do
          :never -> :ok
        end
      end
    end

    ring = Ring.new(1, wake_message: :ready, test_hook: hook)
    {producer, monitor} = spawn_monitor(fn -> Ring.enqueue(ring, :packet) end)
    assert_receive :ready
    assert_receive {:stopped, ^producer}
    Process.exit(producer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^producer, :killed}
    assert Ring.take(ring) == expected
  end

  defp holding_hook(parent) do
    fn
      :after_journal ->
        if self() != parent do
          send(parent, {:holding, self()})

          receive do
            :release -> :ok
          end
        end

      _phase ->
        :ok
    end
  end

  defp contend_many(ring, count, index \\ 0) do
    :timer.tc(fn ->
      Enum.reduce(1..count, %{}, fn sequence, results ->
        Map.update(results, Ring.enqueue(ring, {index, sequence}), 1, &(&1 + 1))
      end)
    end)
  end

  defp await_ring do
    receive do
      {:ring, ring} -> consume(ring, 0)
    end
  end

  defp consume(ring, count) do
    receive do
      {:stop, from} -> send(from, {:consumed, drain(ring, count)})
      :ready -> consume(ring, drain(ring, count))
    end
  end

  defp drain(ring, count) do
    case Ring.take(ring) do
      {:ok, _item} -> drain(ring, count + 1)
      :busy -> drain(ring, count)
      _empty_or_closed -> count
    end
  end

  defp contend(ring, parent) do
    Ring.enqueue(ring, :contended)
    send(parent, {:contending, self()})
    contend_forever(ring)
  end

  defp contend_forever(ring) do
    Ring.enqueue(ring, :contended)
    contend_forever(ring)
  end
end
