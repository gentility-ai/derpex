defmodule Derpex.Outbox.RingTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Lock
  alias Derpex.Outbox.Ring

  @enqueue_results [{:ok, :wake}, {:ok, :coalesced}, {:ok, :replaced}, {:dropped, :contention}]
  # Roughly two hundred microseconds of work between packets, so that eight
  # senders keep the schedulers busy without saturating them.
  @pacing_iterations 100_000

  test "coalesces wakeups and replaces the oldest item at fixed capacity" do
    ring = Ring.new(2, wake_message: :ready)

    assert Ring.enqueue(ring, :first) == {:ok, :wake}
    assert_receive :ready
    assert Ring.enqueue(ring, :second) == {:ok, :coalesced}
    assert Ring.enqueue(ring, :third) == {:ok, :replaced}
    refute_receive :ready

    assert Ring.stats(ring) == %{
             capacity: 2,
             full_policy: :replace,
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

  test "a held lock turns every producer attempt into a counted tail drop" do
    parent = self()
    ring = Ring.new(1, wake_message: :ready, test_hook: holding_hook(parent))
    {holder, holder_monitor} = spawn_monitor(fn -> Ring.enqueue(ring, :first) end)
    assert_receive {:holding, ^holder}

    assert Ring.enqueue(ring, :second) == {:dropped, :contention}

    # Every attempt against a lock that is never released gives up inside its
    # bounded retry budget instead of waiting for the holder, so the contender
    # finishes all of its attempts while the lock is still held.
    attempts = 5

    {contender, contender_monitor} =
      spawn_monitor(fn -> send(parent, {:attempted, contend_many(ring, attempts)}) end)

    assert_receive {:attempted, {_latencies, results}}, 5_000
    assert_receive {:DOWN, ^contender_monitor, :process, ^contender, :normal}
    assert results == %{{:dropped, :contention} => attempts}

    send(holder, :release)
    assert_receive {:DOWN, ^holder_monitor, :process, ^holder, :normal}
    assert_receive :ready
    assert Ring.take(ring) == {:ok, :first}
    assert Ring.stats(ring).tail_drops == attempts + 1
  end

  # Saturating fan-in is the worst case for a single ring lock: eight producers
  # that never pause exhaust their retry budgets and take counted tail drops.
  # What must hold is that nothing is lost silently.
  @tag timeout: 30_000
  test "concurrent producers keep every item delivered or counted" do
    parent = self()
    producer_count = 8
    per_producer = 200
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
      Enum.reduce(outcomes, %{}, fn {_latencies, counts}, tally ->
        Map.merge(tally, counts, fn _result, left, right -> left + right end)
      end)

    assert Map.keys(results) -- @enqueue_results == []
    assert Map.get(results, {:dropped, :contention}, 0) == stats.tail_drops
    assert delivered + stats.head_drops + stats.tail_drops == sent
    assert delivered > 0
  end

  # The relay's ordinary case: one sender filling one destination's ring while
  # its writer drains, with fewer packets in flight than the ring has slots.
  # Nothing may be dropped or reordered there, which is exactly what the Go
  # prober checks over its hundred megabytes.
  @tag timeout: 30_000
  test "one producer and one consumer deliver every item in order without drops" do
    parent = self()
    total = 10_000
    window = 24
    consumer = spawn_link(fn -> await_ordered_ring(parent, total) end)
    ring = Ring.new(32, notifier: consumer, wake_message: :ready)
    send(consumer, {:ring, ring})

    outstanding =
      Enum.reduce(1..total, 0, fn sequence, outstanding ->
        outstanding = await_credit(outstanding, window)
        # Retrying a contention drop keeps the sequence intact: the item was
        # never published, and this is the only producer.
        assert enqueue_until_accepted(ring, sequence) in [:wake, :coalesced]
        outstanding + 1
      end)

    _drained = await_credit(outstanding, 1)
    assert_receive {:verified, ^total}, 5_000
    refute_received {:out_of_order, _expected, _item}

    stats = Ring.stats(ring)
    assert stats.head_drops == 0
    assert stats.size == 0
    # Losing the lock to the writer stays exceptional even on a loaded machine.
    assert stats.tail_drops < div(total, 100)
  end

  # Eight senders sharing one destination wait for its ring lock; what they must
  # not do is wait for it indefinitely.
  @tag timeout: 30_000
  test "an enqueue stays inside the acquisition budget under concurrent producers" do
    parent = self()
    producer_count = 8
    per_producer = 200
    consumer = spawn_link(&await_ring/0)
    ring = Ring.new(32, notifier: consumer, wake_message: :ready)
    send(consumer, {:ring, ring})

    producers =
      Enum.map(1..producer_count, fn index ->
        spawn_monitor(fn ->
          {latencies, _results} = contend_many(ring, per_producer, index, @pacing_iterations)
          send(parent, {:latencies, self(), latencies})
        end)
      end)

    # A one-millisecond nap costs a millisecond only on an idle node; behind a
    # busy run queue it costs whatever rescheduling costs. Calibrating against
    # that same load while the producers run keeps the ceiling a statement
    # about the ring — its budget and the naps that fit in it — rather than
    # about the machine. A hundred samples rather than a handful, because it is
    # the tail of that cost the ceiling has to cover.
    nap_cost = Enum.max(for _sample <- 1..100, do: elem(:timer.tc(&Process.sleep/1, [1]), 0))
    ceiling = Lock.budget_microseconds() + Lock.nap_allowance() * nap_cost

    latencies =
      Enum.flat_map(producers, fn {producer, monitor} ->
        assert_receive {:latencies, ^producer, samples}, 30_000
        assert_receive {:DOWN, ^monitor, :process, ^producer, :normal}, 5_000
        samples
      end)

    send(consumer, {:stop, self()})
    assert_receive {:consumed, _delivered}, 5_000

    assert percentile(latencies, 0.999) <= ceiling
    # The typical enqueue does not cost even one nap.
    assert percentile(latencies, 0.5) <= nap_cost
  end

  test "a producer killed while contending never wedges the consumer" do
    parent = self()
    ring = Ring.new(4, wake_message: :ready, test_hook: holding_hook(parent))
    {holder, holder_monitor} = spawn_monitor(fn -> Ring.enqueue(ring, :held) end)

    assert_receive {:holding, ^holder}

    Enum.each(1..5, fn _attempt ->
      {producer, producer_monitor} = spawn_monitor(fn -> contend(ring, parent) end)
      assert_receive {:contending, ^producer}
      await_parked(producer)
      Process.exit(producer, :kill)
      assert_receive {:DOWN, ^producer_monitor, :process, ^producer, :killed}
    end)

    send(holder, :release)
    assert_receive {:DOWN, ^holder_monitor, :process, ^holder, :normal}

    # The wakeup follows the release, not the publish, so it arrives once the
    # writer can actually take what it is being woken for.
    assert_receive :ready
    assert Ring.take(ring) == {:ok, :held}
  end

  test "recovers a producer killed before or after slot publication" do
    assert_stale_producer_recovery(:after_journal, :empty)
    assert_stale_producer_recovery(:after_publish, {:ok, :packet})
  end

  test "a ring carrying both classes labels each drop from the packet" do
    ring = Ring.new(1, metrics: Derpex.Metrics.default_handle(), metric_kind: :by_packet)
    disco = <<0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC>> <> :binary.copy(<<7>>, 56)
    before = Derpex.Metrics.snapshot()

    assert Ring.enqueue(ring, {:forward_packet, <<0::256>>, <<1::256>>, disco}) == {:ok, :wake}

    assert Ring.enqueue(ring, {:forward_packet, <<0::256>>, <<1::256>>, "plain"}) ==
             {:ok, :replaced}

    assert Ring.enqueue(ring, {:forward_packet, <<0::256>>, <<1::256>>, "again"}) ==
             {:ok, :replaced}

    current = Derpex.Metrics.snapshot()

    assert current[{:packets_dropped, :queue_head, :disco}] -
             before[{:packets_dropped, :queue_head, :disco}] == 1

    assert current[{:packets_dropped, :queue_head, :other}] -
             before[{:packets_dropped, :queue_head, :other}] == 1

    assert current[{:bytes_dropped, :queue_head, :disco}] -
             before[{:bytes_dropped, :queue_head, :disco}] == byte_size(disco)
  end

  test "a ring that refuses replacement keeps the item it already holds" do
    ring = Ring.new(1, wake_message: :ready, full: :reject)

    assert Ring.enqueue(ring, :first) == {:ok, :wake}
    assert Ring.enqueue(ring, :second) == {:dropped, :queue_full}
    assert Ring.stats(ring).tail_drops == 1
    assert Ring.take(ring) == {:ok, :first}
    assert Ring.take(ring) == :empty
  end

  test "replacing the oldest packet still records how long it waited" do
    ring =
      Ring.new(1,
        wake_message: :ready,
        metrics: Derpex.Metrics.default_handle(),
        metric_kind: :other
      )

    assert Ring.enqueue(ring, {:recv_packet, <<0::256>>, "first"}) == {:ok, :wake}
    Process.sleep(2)
    before = Derpex.Metrics.snapshot().average_queue_duration_ms
    assert Ring.enqueue(ring, {:recv_packet, <<0::256>>, "second"}) == {:ok, :replaced}

    # Go feeds a head-dropped packet's residence time into the same moving
    # average as a delivered one, so a queue that is dropping still shows how
    # long it is making packets wait.
    assert Derpex.Metrics.snapshot().average_queue_duration_ms != before
  end

  test "an idle ring costs a bounded amount of table memory" do
    ring = Ring.new(32)

    # Every access is serialised by the ring lock, so the table needs none of
    # the per-scheduler structures that decorated concurrency options allocate.
    assert Ring.memory_words(ring) < 4_096
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
    assert_receive {:stopped, ^producer}
    Process.exit(producer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^producer, :killed}
    assert Ring.take(ring) == expected

    # A producer that died mid-publish sent no wakeup, and left none claimed:
    # the next enqueue wakes the writer rather than coalescing into a message
    # that was never sent.
    assert Ring.enqueue(ring, :after_the_kill) == {:ok, :wake}
    assert_receive :ready
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

  # Returns how each attempt ended and how long each one took. `pace` is the
  # work a producer does between packets; zero saturates the schedulers.
  defp contend_many(ring, count, index \\ 0, pace \\ 0) do
    Enum.map_reduce(1..count, %{}, fn sequence, results ->
      spin(pace)
      {microseconds, result} = :timer.tc(fn -> Ring.enqueue(ring, {index, sequence}) end)
      {microseconds, Map.update(results, result, 1, &(&1 + 1))}
    end)
  end

  defp spin(0), do: :ok
  defp spin(iterations), do: spin(iterations - 1)

  defp enqueue_until_accepted(ring, item) do
    case Ring.enqueue(ring, item) do
      {:ok, wake_state} -> wake_state
      {:dropped, :contention} -> enqueue_until_accepted(ring, item)
    end
  end

  defp percentile(samples, fraction) do
    sorted = Enum.sort(samples)
    index = min(round(length(sorted) * fraction), length(sorted) - 1)
    Enum.at(sorted, index)
  end

  defp await_ring do
    receive do
      {:ring, ring} -> consume(ring, 0)
    end
  end

  defp await_credit(outstanding, window) when outstanding < window, do: outstanding

  defp await_credit(outstanding, window) do
    receive do
      {:consumed, count} -> await_credit(outstanding - count, window)
    after
      5_000 -> flunk("the consumer stopped taking items")
    end
  end

  defp await_ordered_ring(parent, total) do
    receive do
      {:ring, ring} -> consume_in_order(ring, parent, total, 1)
    end
  end

  defp consume_in_order(_ring, parent, total, expected) when expected > total do
    send(parent, {:verified, total})
  end

  defp consume_in_order(ring, parent, total, expected) do
    receive do
      :ready ->
        expected = take_in_order(ring, parent, expected, 0)
        consume_in_order(ring, parent, total, expected)
    end
  end

  defp take_in_order(ring, parent, expected, taken) do
    case Ring.take(ring) do
      {:ok, ^expected} ->
        take_in_order(ring, parent, expected + 1, taken + 1)

      {:ok, item} ->
        send(parent, {:out_of_order, expected, item})
        expected

      :busy ->
        take_in_order(ring, parent, expected, taken)

      _empty_or_closed ->
        if taken > 0, do: send(parent, {:consumed, taken})
        expected
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
    send(parent, {:contending, self()})
    contend_forever(ring)
  end

  # The kill has to land while the producer is inside a retry, which is where a
  # producer spends nearly all of its time against a lock that is never
  # released. Waiting for the parked state keeps that deterministic without
  # depending on how long a retry takes.
  defp await_parked(producer, attempts \\ 10_000)

  defp await_parked(_producer, 0) do
    flunk("the producer never parked inside its retry budget")
  end

  defp await_parked(producer, attempts) do
    # Sampling on a millisecond timer aliases with the producer's own
    # millisecond naps and reports it runnable every time; yielding samples the
    # gaps too.
    if Process.info(producer, :status) == {:status, :waiting} do
      :ok
    else
      :erlang.yield()
      await_parked(producer, attempts - 1)
    end
  end

  defp contend_forever(ring) do
    Ring.enqueue(ring, :contended)
    contend_forever(ring)
  end
end
