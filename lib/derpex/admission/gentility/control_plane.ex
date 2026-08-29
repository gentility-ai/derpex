defmodule Derpex.Admission.Gentility.ControlPlane do
  @moduledoc """
  Transport boundary implemented by the Gentility control-plane integration.

  DERPEX deliberately does not prescribe HTTP, gRPC, or message-bus transport.
  Returned lease and revocation records are authenticated by contract v1.

  ## Authorization answers

  `c:authorize/2` has exactly two authoritative answers, and both are signed
  contract v1 records returned as `{:ok, wire}`:

    * an admission lease (`DXAL`) for the requested node key admits, and
    * a revocation (`DXRV`) for the requested node key denies, dropping the
      cached lease and closing that node's established connections.

  `{:error, reason}` means the control plane could not answer. It is never a
  denial, whatever the reason term is — `:unavailable`, `{:http, 503}`,
  `{:http, 403}`, `:closed`, or anything else. DERPEX treats every error, every
  timeout, every exit, and every unrecognized return value alike: it serves the
  cached lease for that node key if one is still unexpired, and rejects the
  connection with `:no_cached_lease` if none is. An implementation that wants a
  node rejected during an outage must therefore have published a signed
  revocation, or let its lease expire; it must not encode denial as an error.
  """

  alias Derpex.Admission.Request

  @type cursor :: binary()

  @callback authorize(Request.t(), term()) :: {:ok, binary()} | {:error, term()}
  @callback export_usage(<<_::256>>, binary(), term()) :: :ok | {:ok, term()} | {:error, term()}
  @callback reconcile(term()) :: {:ok, [binary()], cursor()} | {:error, term()}
  @callback next_revocation(cursor(), pos_integer(), term()) ::
              {:ok, binary(), cursor()} | {:timeout, cursor()} | {:error, term()}
end
