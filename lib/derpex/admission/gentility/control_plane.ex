defmodule Derpex.Admission.Gentility.ControlPlane do
  @moduledoc """
  Transport boundary implemented by the Gentility control-plane integration.

  DERPEX deliberately does not prescribe HTTP, gRPC, or message-bus transport.
  Returned lease and revocation records are authenticated by contract v1.

  ## Authorization answers

  `c:authorize/2` has exactly two authoritative answers, and both are signed
  contract v1 records returned as `{:ok, wire}`:

    * an admission lease (`DXAL`) for the requested node key admits, and
    * a revocation (`DXRV`) for the requested node key denies every lease it
      covers, dropping the cached lease and closing that node's established
      connections.

  ## Renewals

  A lease serving an established connection is re-authorized in the background
  at 80% of its lifetime. That call arrives through the same `c:authorize/2`
  with `metadata: %{renewal: true}`, `client_info: nil`, and `source_ip: nil`:
  it re-authorizes an identity the relay already holds rather than a new
  connection, so an adapter must key it on the node key alone. Answering it
  with a lease replaces the cached one without disturbing the connection;
  answering with an error leaves the existing lease serving until it expires;
  answering with a revocation closes the node as any denial does.

  A revocation denies only leases whose policy revision it covers. Answering
  with a revocation older than the node's cached lease — or replaying one the
  relay already holds — does not deny the node: the cached lease still stands
  and admission continues from it. Denying a node that holds a newer lease
  requires a revocation at that lease's revision or above.

  `{:error, reason}` means the control plane could not answer. It is never a
  denial, whatever the reason term is — `:unavailable`, `{:http, 503}`,
  `{:http, 403}`, `:closed`, or anything else. DERPEX treats every error, every
  timeout, every exit, and every unrecognized return value alike: it serves the
  cached lease for that node key if one is still unexpired, and rejects the
  connection with `:no_cached_lease` if none is. An implementation that wants a
  node rejected during an outage must therefore have published a signed
  revocation, or let its lease expire; it must not encode denial as an error.

  ## Reconciliation

  `c:reconcile/2` replays the revocations DERPEX may have missed while it was
  disconnected. It is called with `nil` to begin a pass and with the cursor from
  the previous page to continue one. The cursor in a reply is the position after
  the records it carries:

    * a cursor means more records may follow — DERPEX calls again with it, and
    * `nil` ends the pass and DERPEX resumes streaming from the last cursor it
      was given.

  An adapter therefore returns its end position as the cursor on the last page
  of records and answers `{:ok, [], nil}` to the call after it. Pages are
  bounded by record count and bytes, and a pass is bounded by page count, so a
  reconciliation that never ends is abandoned and retried rather than run
  forever.

  The two cursors are distinct. A reconciliation cursor is `nil` at the start of
  a pass and `nil` again to end one. A stream cursor is always a binary: it
  begins as `""` — meaning "from wherever you would start a fresh consumer" —
  and is thereafter whatever `c:next_revocation/3` last returned, including
  across a timeout. `nil` is never a stream position.

  Gentility prunes revocations older than the maximum lease lifetime
  (`DERPEX_GENTILITY_MAX_LEASE_MS`): every lease such a record could still deny
  has expired by then, so a reconciliation only has to replay that window.
  """

  alias Derpex.Admission.Request

  @type cursor :: binary()

  @callback authorize(Request.t(), term()) :: {:ok, binary()} | {:error, term()}
  @callback export_usage(<<_::256>>, binary(), term()) :: :ok | {:ok, term()} | {:error, term()}
  @callback reconcile(nil | cursor(), term()) ::
              {:ok, [binary()], nil | cursor()} | {:error, term()}
  @callback next_revocation(cursor(), pos_integer(), term()) ::
              {:ok, binary(), cursor()} | {:timeout, cursor()} | {:error, term()}
end
