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

Verification keys are configured as a bounded key-ID map. Rotation publishes
the new public key before Gentility signs with it and retains the old key until
every lease it signed has expired. DERPEX rejects unknown key IDs, signatures
that do not verify, leases issued beyond configured clock skew, expired leases,
and leases longer than the configured maximum. Expiry is never extended by the
clock-skew allowance.

The canonical SHA-256 vectors in `ContractTest` are the language-neutral v1
fixtures. Any Gentility implementation must produce those exact records before
the joint contract gate passes.

## Consequences

- Cached authorization remains verifiable without a live control-plane call.
- A signing-key compromise is separate from the DERP server identity and can
  be rotated by key ID.
- The format deliberately avoids JSON canonicalization and serialization
  libraries in the relay critical path.
- Contract evolution requires a new version; unknown versions fail closed.
- Regional budgets are authoritative local allocations. Global coordination
  and billing export remain separate protocols layered on the lease fields.
