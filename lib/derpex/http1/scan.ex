defmodule Derpex.HTTP1.Scan do
  @moduledoc """
  Boundary-aware terminator search for incrementally buffered HTTP bytes.

  Rescanning the whole buffer after every read makes a slow trickle of header
  bytes quadratic in the buffer size. `match_from/3` rescans only the tail that
  could still hold a terminator straddling the previous read boundary.
  """

  @doc """
  Finds `pattern` in `buffer`, skipping the first `scanned` bytes apart from the
  `byte_size(pattern) - 1` byte overlap a straddling match needs.

  Returned positions are absolute, exactly as `:binary.match/2` reports them. A
  `scanned` offset past the end of `buffer` is clamped, so a stale offset can
  only cost a wider scan, never a bad scope.
  """
  @spec match_from(binary(), non_neg_integer(), binary()) ::
          {non_neg_integer(), pos_integer()} | :nomatch
  def match_from(buffer, scanned, pattern)
      when is_binary(buffer) and is_integer(scanned) and scanned >= 0 and
             is_binary(pattern) and byte_size(pattern) > 0 do
    start = max(0, min(scanned, byte_size(buffer)) - (byte_size(pattern) - 1))
    :binary.match(buffer, pattern, scope: {start, byte_size(buffer) - start})
  end
end
