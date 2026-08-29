# ADR 0002: Gentility admission contract v1

Status: accepted

## Context

DERPEX must reconnect a previously authorized node during a bounded Gentility
outage without accepting unknown or revoked nodes indefinitely. The cached
decision therefore has to be portable, authenticated, explicitly expiring,
and independently verifiable by every relay instance. Revocation delivery also
crosses an untrusted network and must not depend on transport authentication
alone.

## Decision

Contract v1 uses canonical binary records authenticated by Ed25519. Every
record begins with a four-byte type magic and a two-byte version. Integers are
unsigned, big-endian, and fixed width. Text is non-empty UTF-8 prefixed by an
unsigned 16-bit byte length. The final 64 bytes are the Ed25519 signature over
all preceding bytes.

An authorization lease contains, in order:

1. magic `DXAL`, version `1`, and signing-key ID;
2. the 32-byte DERP node public key;
3. Gentility node, organization, owner-kind, and deployment identifiers;
4. region ID, policy revision, and quota revision;
5. issue and exclusive-expiry Unix times in milliseconds; and
6. allocated node/organization connection limits plus byte rates and bursts.

A revocation contains magic `DXRV`, version `1`, signing-key ID, node key,
policy revision, revocation Unix time in milliseconds, and a bounded reason.
Revocation revision `R` invalidates leases for that node whose policy revision
is at most `R`.

Authorization has exactly two authoritative answers, and both are signed
records: a lease admits the requested node key, and a revocation for that node
key denies it, dropping any cached lease and closing its established
connections. An error returned by the control-plane transport is a failure to
answer, never a denial, whatever its reason term. DERPEX therefore treats every
error tuple, timeout, exit, and unrecognized return value identically: it
serves the cached lease for that node key while one is unexpired, and rejects
the connection once none is. Encoding a denial as an error — an HTTP 403, for
instance — would make a control-plane outage indistinguishable from a mass
denial and would darken every relay the moment Gentility became unreachable.
Denial during an outage is expressed by a previously published revocation or by
lease expiry, which bounds the worst case at the maximum lease lifetime.

Verification keys are configured as a bounded key-ID map. Rotation publishes
the new public key before Gentility signs with it and retains the old key until
every lease it signed has expired. DERPEX rejects unknown key IDs, signatures
that do not verify, leases issued beyond configured clock skew, expired leases,
and leases longer than the configured maximum. Expiry is never extended by the
clock-skew allowance.

The canonical SHA-256 vectors in `ContractTest` are the language-neutral v1
fixtures. Any Gentility implementation must produce those exact records before
the joint contract gate passes.

Usage export uses a separate canonical `DXUB` version-1 record. It identifies
the DERPEX instance, region, fixed window, and sorted sender-attribution
entries. Entries contain Gentility node, organization, owner kind, deployment,
and accepted/dropped packet and byte totals. They never contain a destination,
peer relationship, payload, source IP, or packet timing. A batch carries at most 10 000
entries and at most 8 MiB of wire; a window exceeding either bound is exported
as several batches that share its bounds, each content-addressed independently. The SHA-256 digest
of the complete record is its idempotency key. Export transport must authenticate
the DERPEX instance; usage records are not bearer authorization and are not
individually signed. `UsageContractTest` fixes the cross-language vector.

## Consequences

- Cached authorization remains verifiable without a live control-plane call.
- A signing-key compromise is separate from the DERP server identity and can
  be rotated by key ID.
- The format deliberately avoids JSON canonicalization and serialization
  libraries in the relay critical path.
- Contract evolution requires a new version; unknown versions fail closed.
- A batch that cannot be encoded is bisected, not discarded. Only a single row
  that still fails alone is dropped: it is logged, counted in
  `derpex_gentility_usage_dropped_rows`, and deleted. Losing one row of
  accounting is preferable to a window that can never drain and therefore sheds
  every relayed packet behind it; losing the window with it is not.
- Regional budgets are authoritative local allocations. Global coordination
  and billing export remain separate protocols layered on the lease fields.
