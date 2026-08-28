defmodule Derpex.Outbox.RingTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Ring

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

  test "contention is a non-blocking tail drop" do
    parent = self()

    hook = fn
      :after_journal ->
        if self() != parent do
          send(parent, {:journaled, self()})

          receive do
            :continue -> :ok
          end
        end

      _phase ->
        :ok
    end

    ring = Ring.new(1, wake_message: :ready, test_hook: hook)
    producer = spawn(fn -> Ring.enqueue(ring, :first) end)
    assert_receive {:journaled, ^producer}

    started_at = System.monotonic_time()
    assert Ring.enqueue(ring, :second) == {:dropped, :contention}
    elapsed = System.monotonic_time() - started_at
    assert elapsed < System.convert_time_unit(100, :millisecond, :native)

    send(producer, :continue)
    assert_receive :ready
    assert eventually(fn -> Ring.stats(ring) != :busy end)
    assert Ring.take(ring) == {:ok, :first}
    assert Ring.stats(ring).tail_drops == 1
  end

  test "producer and consumer contention does not drop below capacity" do
    ring = Ring.new(32, wake_message: :ready)
    parent = self()

    consumer =
      spawn(fn ->
        Enum.each(1..10_000, fn expected ->
          item = take_when_ready(ring)
          send(parent, {:taken, item})

          if item != expected do
            exit({:out_of_order, expected, item})
          end
        end)
      end)

    monitor = Process.monitor(consumer)

    Enum.each(1..10_000, fn sequence ->
      if sequence > 30 do
        assert_receive {:taken, expected} when expected == sequence - 30
      end

      assert Ring.enqueue(ring, sequence) in [{:ok, :wake}, {:ok, :coalesced}]
    end)

    Enum.each(9_971..10_000, fn expected ->
      assert_receive {:taken, ^expected}
    end)

    assert_receive {:DOWN, ^monitor, :process, ^consumer, :normal}
    assert Ring.stats(ring).tail_drops == 0
    assert Ring.stats(ring).head_drops == 0
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

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(1)
      eventually(fun, attempts - 1)
    end
  end

  defp take_when_ready(ring) do
    case Ring.take(ring) do
      {:ok, item} -> item
      _empty_or_busy -> take_when_ready(ring)
    end
  end
end
