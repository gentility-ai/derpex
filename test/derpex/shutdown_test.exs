defmodule Derpex.ShutdownTest do
  use ExUnit.Case, async: true

  alias Derpex.Drain
  alias Derpex.Outbox.Ring
  alias Derpex.Shutdown

  test "returns as soon as every home relinquishes during drain" do
    drain = start_supervised!({Drain, name: nil, profile: :gentility})
    home = spawn(fn -> Process.sleep(:infinity) end)
    assert Drain.register(drain, home, Ring.new(2)) == :ok
    assert Drain.set_preferred(drain, home, true) == :ok

    Task.start(fn ->
      Process.sleep(10)
      Drain.set_preferred(drain, home, false)
    end)

    assert %{outcome: :drained, forced_connections: 0} =
             Shutdown.run(drain, deadline_ms: 1_000, poll_ms: 1, notify?: false)

    Process.exit(home, :kill)
  end

  test "forces remaining homes closed at a hard wall deadline" do
    drain = start_supervised!({Drain, name: nil, profile: :baseline})
    parent = self()
    home = spawn(fn -> relay(parent) end)
    assert Drain.register(drain, home, Ring.new(2)) == :ok
    assert Drain.set_preferred(drain, home, true) == :ok

    assert %{outcome: :deadline, forced_connections: 1, elapsed_ms: elapsed} =
             Shutdown.run(drain, deadline_ms: 5, poll_ms: 1, notify?: false)

    assert elapsed >= 5
    assert_receive {:connection_message, ^home, {:derpex_drain_close, _token}}
    Process.exit(home, :kill)
  end

  test "an unavailable drain coordinator cannot delay shutdown" do
    missing = spawn(fn -> :ok end)
    monitor = Process.monitor(missing)
    assert_receive {:DOWN, ^monitor, :process, ^missing, _reason}

    # The property is that the run does not sit out its own deadline, so the
    # comparison is against that deadline arriving, not against a wall-clock
    # budget that a loaded machine can blow through.
    deadline_ms = 1_000
    deadline = Process.send_after(self(), :deadline_reached, deadline_ms)

    assert %{outcome: :unavailable, forced_connections: 0, elapsed_ms: elapsed} =
             Shutdown.run(missing, deadline_ms: deadline_ms)

    refute_received :deadline_reached
    Process.cancel_timer(deadline)
    assert elapsed < deadline_ms
  end

  defp relay(parent) do
    receive do
      message ->
        send(parent, {:connection_message, self(), message})
        relay(parent)
    end
  end
end
