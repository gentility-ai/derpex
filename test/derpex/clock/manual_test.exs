defmodule Derpex.Clock.ManualTest do
  use ExUnit.Case, async: false

  alias Derpex.Clock.Manual

  setup do
    start_supervised!({Manual, monotonic_time: 100, system_time: 1_000})
    previous = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous) end)
  end

  test "advances time and delivers timers deterministically" do
    first = Derpex.Clock.send_after(self(), :first, 10)
    second = Derpex.Clock.send_after(self(), :second, 10)

    assert is_reference(first)
    assert is_reference(second)
    assert Derpex.Clock.monotonic_time() == 100
    assert Derpex.Clock.system_time() == 1_000

    assert :ok = Manual.advance(9)
    refute_receive _message

    assert :ok = Manual.advance(1)
    assert_receive :first
    assert_receive :second
    assert Derpex.Clock.monotonic_time() == 110
    assert Derpex.Clock.system_time() == 1_010
  end

  test "cancels timers and can adjust wall time independently" do
    timer = Derpex.Clock.send_after(self(), :cancelled, 25)
    assert Derpex.Clock.cancel_timer(timer) == 25
    assert Derpex.Clock.cancel_timer(timer) == false

    assert :ok = Manual.set_system_time(5_000)
    assert Derpex.Clock.system_time() == 5_000

    assert :ok = Manual.advance(25)
    refute_receive :cancelled
  end
end
