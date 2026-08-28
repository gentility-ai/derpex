defmodule Derpex.RateLimiter do
  @moduledoc "A clock-driven token bucket for low-volume protocol controls."

  alias Derpex.Clock

  defstruct [:rate_per_millisecond, :burst, :tokens, :last_millisecond]

  @opaque t :: %__MODULE__{
            rate_per_millisecond: float(),
            burst: pos_integer(),
            tokens: float(),
            last_millisecond: integer()
          }

  @doc "Creates a full token bucket at the current configured-clock instant."
  @spec new(number(), pos_integer()) :: t()
  def new(rate_per_second, burst)
      when is_number(rate_per_second) and rate_per_second > 0 and is_integer(burst) and burst > 0 do
    %__MODULE__{
      rate_per_millisecond: rate_per_second / 1_000,
      burst: burst,
      tokens: burst * 1.0,
      last_millisecond: Clock.monotonic_time(:millisecond)
    }
  end

  @doc "Consumes one token when available and returns the updated bucket."
  @spec allow(t(), integer()) :: {boolean(), t()}
  def allow(%__MODULE__{} = limiter, now_millisecond \\ Clock.monotonic_time(:millisecond)) do
    elapsed = max(now_millisecond - limiter.last_millisecond, 0)

    tokens =
      min(
        limiter.burst * 1.0,
        limiter.tokens + elapsed * limiter.rate_per_millisecond
      )

    if tokens >= 1.0 do
      {true, %{limiter | tokens: tokens - 1.0, last_millisecond: now_millisecond}}
    else
      {false, %{limiter | tokens: tokens, last_millisecond: now_millisecond}}
    end
  end
end
