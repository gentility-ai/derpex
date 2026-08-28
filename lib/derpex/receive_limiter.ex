defmodule Derpex.ReceiveLimiter do
  @moduledoc "Clock-driven byte token bucket matching DERP receive-frame pacing."

  alias Derpex.Clock
  alias Derpex.RateConfig

  defstruct [:rate_per_microsecond, :burst, :tokens, :last_microsecond]

  @opaque t :: %__MODULE__{
            rate_per_microsecond: float(),
            burst: pos_integer(),
            tokens: float(),
            last_microsecond: integer()
          }

  @doc "Creates a full bucket from a normalized non-zero rate configuration."
  @spec new(RateConfig.t(), integer()) :: t()
  def new(%RateConfig{} = config, now_microsecond \\ Clock.monotonic_time(:microsecond)) do
    config = RateConfig.normalize(config)
    rate = config.per_client_rate_limit_bytes_per_second
    burst = config.per_client_rate_burst_bytes

    if rate == 0 do
      raise ArgumentError, "receive limiter requires a non-zero byte rate"
    end

    new(rate, burst, now_microsecond)
  end

  @doc false
  @spec new(pos_integer(), pos_integer(), integer()) :: t()
  def new(rate, burst, now_microsecond)
      when is_integer(rate) and rate > 0 and is_integer(burst) and burst > 0 do
    %__MODULE__{
      rate_per_microsecond: rate / 1_000_000,
      burst: burst,
      tokens: burst * 1.0,
      last_microsecond: now_microsecond
    }
  end

  @doc "Reserves one frame body and returns its required delay in microseconds."
  @spec reserve(t(), non_neg_integer(), integer()) ::
          {:ok, non_neg_integer(), t()} | {:error, :exceeds_burst}
  def reserve(
        %__MODULE__{} = limiter,
        frame_length,
        now_microsecond \\ Clock.monotonic_time(:microsecond)
      )
      when is_integer(frame_length) and frame_length >= 0 do
    tokens = refill(limiter, now_microsecond)
    cost = min(frame_length, RateConfig.minimum_burst())

    if cost > limiter.burst do
      {:error, :exceeds_burst}
    else
      remaining = tokens - cost
      delay = if remaining < 0, do: ceil(-remaining / limiter.rate_per_microsecond), else: 0

      {:ok, delay, %{limiter | tokens: remaining, last_microsecond: now_microsecond}}
    end
  end

  defp refill(limiter, now_microsecond) do
    elapsed = max(now_microsecond - limiter.last_microsecond, 0)
    min(limiter.burst * 1.0, limiter.tokens + elapsed * limiter.rate_per_microsecond)
  end
end
