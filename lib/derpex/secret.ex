defmodule Derpex.Secret do
  @moduledoc """
  Reference to key material that renders without its bytes.

  A secret is held in the environment of a zero-arity closure. What this buys
  is **rendering**, not containment: `inspect/2`, `GenServer` crash reports,
  `:sys.get_state/1`, and supervisor child specifications show
  `#Function<...>` instead of the key. The bytes are still reachable through
  `:erlang.fun_info(secret, :env)`, still serialized by `:erlang.term_to_binary/1`,
  and still written to `erl_crash.dump` and to a core dump. Treat a secret as a
  redaction of accidental logging, never as a key-storage boundary.

  Wrap once, at the edge where the key is read from configuration or disk, and
  pass the reference down. `wrap/1` rejects an already-wrapped secret and
  `reveal/1` rejects a raw binary, so a double wrap or a missed wrap fails loudly
  rather than silently storing plaintext in process state.

  A closure carries the identity of the module version that created it, so
  secrets created before a `Derpex.Secret` reload raise when revealed
  afterwards. This affects `recompile/0` in an IEx session, not a release.
  """

  @opaque t :: (-> binary())

  @doc "Wraps key material in a reference that renders without its bytes."
  @spec wrap(binary() | nil) :: t() | nil
  def wrap(nil), do: nil
  def wrap(secret) when is_binary(secret), do: fn -> secret end

  @doc "Returns the key material behind a reference."
  @spec reveal(t() | nil) :: binary() | nil
  def reveal(nil), do: nil
  def reveal(secret) when is_function(secret, 0), do: secret.()
end
