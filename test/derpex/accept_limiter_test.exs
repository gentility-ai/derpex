defmodule Derpex.AcceptLimiterTest do
  use ExUnit.Case, async: false

  alias Derpex.AcceptLimiter
  alias Derpex.Clock.Manual

  setup do
    start_supervised!({Manual, monotonic_time: 0})
    previous = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous) end)
  end

  test "shares a bounded burst and refills at the configured accept rate" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {1, 2}})

    assert AcceptLimiter.allow?(limiter)
    assert AcceptLimiter.allow?(limiter)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(999)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(1)
    assert AcceptLimiter.allow?(limiter)
  end

  test "can be disabled or configured as a finite non-refilling burst" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {0, 1}})

    assert AcceptLimiter.allow?(limiter)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(60_000)
    refute AcceptLimiter.allow?(limiter)
    assert AcceptLimiter.update(limiter, nil) == :ok
    assert AcceptLimiter.allow?(limiter)
  end
end
