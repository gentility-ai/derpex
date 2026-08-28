defmodule Derpex.ReceiveLimiterTest do
  use ExUnit.Case, async: true

  alias Derpex.RateConfig
  alias Derpex.ReceiveLimiter

  @minimum RateConfig.minimum_burst()

  test "admits the initial burst and predicts the upstream one-second refill wait" do
    config = %RateConfig{
      per_client_rate_limit_bytes_per_second: @minimum,
      per_client_rate_burst_bytes: @minimum
    }

    limiter = ReceiveLimiter.new(config, 0)
    assert {:ok, 0, limiter} = ReceiveLimiter.reserve(limiter, @minimum, 0)
    assert {:ok, 1_000_000, limiter} = ReceiveLimiter.reserve(limiter, @minimum, 0)
    assert {:ok, 1_000_000, _limiter} = ReceiveLimiter.reserve(limiter, @minimum, 1_000_000)
  end

  test "clamps unexpected large frame costs to the maximum SendPacket body" do
    config = %RateConfig{
      per_client_rate_limit_bytes_per_second: @minimum,
      per_client_rate_burst_bytes: @minimum
    }

    limiter = ReceiveLimiter.new(config, 0)
    assert {:ok, 0, _limiter} = ReceiveLimiter.reserve(limiter, 0xFFFFFFFF, 0)
  end

  test "rejects a reservation larger than a generic bucket burst" do
    limiter = ReceiveLimiter.new(10, 5, 0)
    assert ReceiveLimiter.reserve(limiter, 10, 0) == {:error, :exceeds_burst}
  end
end
