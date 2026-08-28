defmodule Derpex.Clock.SystemTest do
  use ExUnit.Case, async: true

  test "reads configured clocks" do
    assert is_integer(Derpex.Clock.monotonic_time())
    assert is_integer(Derpex.Clock.system_time())
  end

  test "schedules and cancels timers" do
    timer = Derpex.Clock.send_after(self(), :tick, 0)
    assert is_reference(timer)
    assert_receive :tick

    timer = Derpex.Clock.send_after(self(), :never, 60_000)
    assert is_integer(Derpex.Clock.cancel_timer(timer))
    refute_receive :never
  end
end
