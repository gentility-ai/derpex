defmodule Derpex.RateLimiterTest do
  use ExUnit.Case, async: true

  alias Derpex.RateLimiter

  test "starts full, caps its burst, and refills at the configured rate" do
    limiter = RateLimiter.new(1, 3)
    now = limiter.last_millisecond

    assert {true, limiter} = RateLimiter.allow(limiter, now)
    assert {true, limiter} = RateLimiter.allow(limiter, now)
    assert {true, limiter} = RateLimiter.allow(limiter, now)
    assert {false, limiter} = RateLimiter.allow(limiter, now)
    assert {false, limiter} = RateLimiter.allow(limiter, now + 999)
    assert {true, limiter} = RateLimiter.allow(limiter, now + 1_000)
    assert {false, _limiter} = RateLimiter.allow(limiter, now + 1_000)
  end
end
