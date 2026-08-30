defmodule Derpex.Outbox.RingDeleteTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Ring

  @source :binary.copy(<<0x2A>>, 32)

  test "a deleted ring drops later publishes instead of reaching a reused table" do
    ring = Ring.new(4, notifier: self())

    assert Ring.enqueue(ring, {:recv_packet, @source, "before"}) == {:ok, :wake}
    assert Ring.delete(ring) == :ok
    assert :ets.info(ring.table) == :undefined
    assert Ring.delete(ring) == :ok

    assert Ring.enqueue(ring, {:recv_packet, @source, "after"}) == {:dropped, :closed}
  end

  test "deleting a ring another producer holds still closes it and drops the table" do
    parent = self()

    hook = fn
      :after_publish ->
        send(parent, {:holding, self()})

        receive do
          :release -> :ok
        end

      _phase ->
        :ok
    end

    ring = Ring.new(4, notifier: self(), test_hook: hook)
    producer = spawn(fn -> hold_lock(ring) end)
    assert_receive {:holding, ^producer}, 1_000

    assert Ring.delete(ring) == :ok
    assert :ets.info(ring.table) == :undefined

    assert Ring.enqueue(ring, {:recv_packet, @source, "after"}) == {:dropped, :closed}

    send(producer, :release)
  end

  defp hold_lock(ring) do
    Ring.enqueue(ring, {:recv_packet, @source, "held"})
  rescue
    ArgumentError -> :ok
  end
end
