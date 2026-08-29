defmodule Derpex.Secret do
  @moduledoc """
  Opaque handle keeping key material out of inspected state.

  A secret is held in the environment of a zero-arity closure, so struct
  inspection, supervisor child specifications, and `GenServer` crash reports
  render `#Function<...>` instead of the key bytes. Wrapping and revealing both
  accept a raw binary so callers outside the supervision tree may still pass
  key material directly.
  """

  @opaque t :: (-> binary())

  @doc "Wraps key material in a reference that renders without its bytes."
  @spec wrap(binary() | t() | nil) :: t() | nil
  def wrap(nil), do: nil
  def wrap(secret) when is_function(secret, 0), do: secret
  def wrap(secret) when is_binary(secret), do: fn -> secret end

  @doc "Returns the key material behind a reference, or a raw binary unchanged."
  @spec reveal(binary() | t() | nil) :: binary() | nil
  def reveal(nil), do: nil
  def reveal(secret) when is_function(secret, 0), do: secret.()
  def reveal(secret) when is_binary(secret), do: secret
end
