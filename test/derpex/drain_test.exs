defmodule Derpex.DrainTest do
  use ExUnit.Case, async: false

  alias Derpex.Clock.Manual
  alias Derpex.Drain
  alias Derpex.Outbox.Ring

  setup do
    start_supervised!({Manual, monotonic_time: 0})
    :ok
  end

  test "Gentility drain notifies current homes with bounded jitter and closes at one deadline" do
    drain =
      start_supervised!(
        {Drain, name: nil, profile: :gentility, clock: Manual, jitter: fn maximum -> maximum end}
      )

    home = reporting_connection(self())
    non_home = reporting_connection(self())
    home_ring = Ring.new(4)
    non_home_ring = Ring.new(4)

    assert Drain.register(drain, home, home_ring) == :ok
    assert Drain.register(drain, non_home, non_home_ring) == :ok
    assert Drain.set_preferred(drain, home, true) == :ok

    assert {:ok,
            %{
              draining?: true,
              targeted_connections: 1,
              reconnect_ms: 1_000,
              try_for_ms: 10_000
            }} =
             Drain.begin_drain(drain,
               reconnect_ms: 1_000,
               try_for_ms: 10_000,
               jitter_ms: 500,
               deadline_ms: 2_000
             )

    assert Ring.take(home_ring) == {:ok, {:restarting, 1_500, 10_000}}
    assert Ring.take(non_home_ring) == :empty
    assert Manual.pending_timer_count() == 1

    # Repeated operator requests do not enqueue duplicate notices or deadlines.
    assert {:ok, %{targeted_connections: 1}} = Drain.begin_drain(drain, deadline_ms: 5_000)
    assert Ring.take(home_ring) == :empty
    assert Manual.pending_timer_count() == 1

    assert Drain.set_preferred(drain, non_home, true) == {:error, :draining}
    assert Drain.set_preferred(drain, non_home, false) == :ok

    :ok = Manual.advance(1_999)
    refute_receive {:connection_message, ^home, _message}
    :ok = Manual.advance(1)
    assert_receive {:connection_message, ^home, {:derpex_drain_close, _token}}
    refute_receive {:connection_message, ^non_home, _message}

    assert %{
             draining?: true,
             accepting_home?: false,
             targeted_connections: 0,
             deadline_remaining_ms: nil,
             notifications_enqueued: 1,
             notification_drops: 0,
             deadline_closes: 1
           } = Drain.stats(drain)

    Process.exit(home, :kill)
    Process.exit(non_home, :kill)
  end

  test "baseline drain never emits restarting and rollback cancels its deadline" do
    drain = start_supervised!({Drain, name: nil, profile: :baseline, clock: Manual})
    home = reporting_connection(self())
    ring = Ring.new(2)

    assert Drain.register(drain, home, ring) == :ok
    assert Drain.set_preferred(drain, home, true) == :ok
    assert {:ok, %{targeted_connections: 1}} = Drain.begin_drain(drain, deadline_ms: 1_000)
    assert Ring.take(ring) == :empty
    assert Drain.stats(drain).notifications_enqueued == 0

    assert Drain.cancel(drain) == :ok
    assert Manual.pending_timer_count() == 0
    assert Drain.set_preferred(drain, home, true) == :ok
    :ok = Manual.advance(1_000)
    refute_receive {:connection_message, ^home, _message}
    refute Drain.stats(drain).draining?

    Process.exit(home, :kill)
  end

  test "relinquishing home status and abrupt exits repair the targeted set" do
    drain = start_supervised!({Drain, name: nil, profile: :gentility, clock: Manual})
    first = reporting_connection(self())
    second = reporting_connection(self())

    for connection <- [first, second] do
      assert Drain.register(drain, connection, Ring.new(2)) == :ok
      assert Drain.set_preferred(drain, connection, true) == :ok
    end

    assert {:ok, %{targeted_connections: 2}} =
             Drain.begin_drain(drain, notify?: false, deadline_ms: 1_000)

    assert Drain.set_preferred(drain, first, false) == :ok
    Process.exit(second, :kill)
    eventually(fn -> Drain.stats(drain).targeted_connections == 0 end)

    :ok = Manual.advance(1_000)
    refute_receive {:connection_message, ^first, _message}
    assert Drain.stats(drain).deadline_closes == 0

    Process.exit(first, :kill)
  end

  test "finishing a drain immediately closes remaining homes exactly once" do
    drain = start_supervised!({Drain, name: nil, profile: :gentility, clock: Manual})
    home = reporting_connection(self())
    assert Drain.register(drain, home, Ring.new(2)) == :ok
    assert Drain.set_preferred(drain, home, true) == :ok
    assert {:ok, %{targeted_connections: 1}} = Drain.begin_drain(drain, deadline_ms: 1_000)

    assert Drain.finish(drain) == {:ok, 1}
    assert_receive {:connection_message, ^home, {:derpex_drain_close, _token}}
    assert Drain.finish(drain) == {:ok, 0}
    refute_receive {:connection_message, ^home, _message}
    assert Drain.stats(drain).deadline_closes == 1
    assert Manual.pending_timer_count() == 0

    Process.exit(home, :kill)
  end

  defp reporting_connection(parent) do
    spawn(fn -> report_messages(parent) end)
  end

  defp report_messages(parent) do
    receive do
      message ->
        send(parent, {:connection_message, self(), message})
        report_messages(parent)
    end
  end

  defp eventually(fun, attempts \\ 100)

  defp eventually(fun, 0), do: assert(fun.())

  defp eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(5)
      eventually(fun, attempts - 1)
    end
  end
end
