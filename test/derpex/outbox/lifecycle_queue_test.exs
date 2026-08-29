defmodule Derpex.Outbox.LifecycleQueueTest do
  @moduledoc """
  The queue's own behaviour. Its lock is `Derpex.Outbox.Lock`, shared with
  `Derpex.Outbox.Ring` and covered by that module's tests, so contention and
  dead-producer recovery are not re-tested here.
  """

  use ExUnit.Case, async: true

  alias Derpex.Outbox.LifecycleQueue

  test "keeps every state change in order, far past any ring capacity" do
    queue = LifecycleQueue.new(wake_message: :ready)
    total = 1_000

    for sequence <- 1..total do
      assert LifecycleQueue.enqueue(queue, {:peer_present, sequence}) in [
               {:ok, :wake},
               {:ok, :coalesced}
             ]
    end

    assert LifecycleQueue.size(queue) == total
    assert LifecycleQueue.stats(queue).size == total

    for sequence <- 1..total do
      assert LifecycleQueue.take(queue) == {:ok, {:peer_present, sequence}}
    end

    assert LifecycleQueue.take(queue) == :empty
  end

  test "coalesces wakeups until the writer sees the queue empty" do
    queue = LifecycleQueue.new(wake_message: :ready)

    assert LifecycleQueue.enqueue(queue, :first) == {:ok, :wake}
    assert_receive :ready
    assert LifecycleQueue.enqueue(queue, :second) == {:ok, :coalesced}
    refute_receive :ready

    assert LifecycleQueue.take(queue) == {:ok, :first}
    assert LifecycleQueue.take(queue) == {:ok, :second}
    assert LifecycleQueue.take(queue) == :empty

    assert LifecycleQueue.enqueue(queue, :third) == {:ok, :wake}
    assert_receive :ready
  end

  test "a watcher that falls past the soft cap has its connection closed" do
    queue = LifecycleQueue.new(soft_cap: 4, owner: self(), wake_message: :ready)

    for sequence <- 1..4 do
      assert {:ok, _wake} = LifecycleQueue.enqueue(queue, sequence)
    end

    assert LifecycleQueue.enqueue(queue, :one_too_many) == {:dropped, :overflow}
    assert_receive {:derpex_lifecycle_overflow, 4}

    # The owner is already closing; every further frame the watcher is owed
    # counts, but none of them tells it again.
    assert LifecycleQueue.enqueue(queue, :and_another) == {:dropped, :overflow}
    refute_receive {:derpex_lifecycle_overflow, _size}
    assert LifecycleQueue.stats(queue).overflow_drops == 2

    # The frames already queued are still owed to the watcher; only the one
    # that would have grown the queue further is refused.
    assert LifecycleQueue.take(queue) == {:ok, 1}
  end

  test "close releases every retained frame and refuses more" do
    queue = LifecycleQueue.new()
    assert {:ok, :wake} = LifecycleQueue.enqueue(queue, :first)

    assert LifecycleQueue.close(queue) == :ok
    assert LifecycleQueue.close(queue) == :ok
    assert LifecycleQueue.take(queue) == :closed
    assert LifecycleQueue.enqueue(queue, :second) == {:dropped, :closed}
    assert LifecycleQueue.size(queue) == 0
  end

  test "a deleted queue reports closure rather than raising" do
    queue = LifecycleQueue.new()
    assert LifecycleQueue.delete(queue) == :ok
    assert LifecycleQueue.delete(queue) == :ok
    assert LifecycleQueue.enqueue(queue, :first) == {:dropped, :closed}
  end
end
