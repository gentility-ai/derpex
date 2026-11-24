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

Gentility prunes revocations older than the configured maximum lease lifetime:
every lease such a record could still deny has expired by then, so
reconciliation only ever has to replay that window. Reconciliation is paged —
each call returns a bounded batch and the position after it, and a `nil`
position ends the pass — so replaying that window never depends on one
unbounded response.

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

## Addendum, v0.2.0: the HTTP plane, confinement, observe, and lanes

Status: accepted. This section adds to the decision above and changes none of
it. The record bytes (`DXAL`, `DXRV`, `DXUB`) are unchanged.

### The HTTP adapter

`Derpex.Admission.Gentility.HTTP` is the `ControlPlane` a relay runs with
`DERPEX_GENTILITY_ADAPTER=http`. It calls three routes on the Gentility app,
`DERPEX_GENTILITY_URL` (https), with `x-derp-instance` set to
`DERPEX_GENTILITY_INSTANCE_ID` and `DERPEX_GENTILITY_TOKEN` (at least 32 bytes)
as a bearer:

- `POST /overlay/derp/authorize` sends the node key in lowercase hex, whether
  the call is a renewal, and the region. A 200 body is the signed record. Every
  other answer is an error, never a denial, as above. A 404 is how Gentility
  says it does not know a key. Like any error, it leaves a key with no cached
  lease refused `no_cached_lease`.
- `GET /overlay/derp/revocations` waits at most 25 s, and 5 s less than the
  stream's own deadline. A 200 carries a `DXRV`, a 204 none; both carry the
  next cursor in `x-derp-cursor`. A 409 means the cursor is gone, and the relay
  reconciles.
- `GET /overlay/derp/reconcile` returns zero or more `DXRV`s, each behind its
  length as an unsigned 16-bit big-endian integer, and the next cursor. A page
  with no cursor ends the pass.

The relay starts with the cursor `""`, and Gentility reads `""` as the start of
its revocation window. After any error on the feed (a 409, any other status,
or a failed call) the relay drops its cursor and reconciles from `""` again.
So a row committed while the relay was away is never skipped.

The relay sends no source address, and logs none.

### Usage is discarded

Gentility has no usage route yet. The HTTP adapter acknowledges every usage
batch and discards it. The batch leaves the spool as if exported, and
`derpex_gentility_usage_discarded_total` counts it. Nothing bills DERP while
this is so. The `DXUB` contract stands for when a route exists.

### Confinement

`DERPEX_GENTILITY_CONFINED_SOURCES` lists address prefixes and the owner kinds
each admits: `<prefix>=<kind>|<kind>;<prefix>=...`. A new connection from a
listed prefix is admitted only if its lease's owner kind equals one of that
prefix's kinds. The compare is of the whole string; a kind is never split.
Otherwise the connection is refused with `confined_source`.

The check runs after the lease is verified, on a live lease and on a cached one
alike, so it holds while Gentility is down. A renewal carries no source and is
not checked again. A source in no listed prefix is unaffected. A source in
several must match the kinds of each.

The loader refuses what it cannot read exactly: a prefix with host bits set,
an unknown kind, and a `computer@<runner id>` whose runner id is not 1 to 55
bytes of lowercase letters, digits and hyphens. An owner kind is at most 64
bytes, and `computer@` is 9.

### Observe

`DERPEX_GENTILITY_ENFORCE` is `1` by default, which is how the plane behaved
before this section. A rollout sets `0` on purpose, first.

With `0`, every decision is made and counted as under `1`, and nothing is
refused or closed:

- A refusal is counted as outcome `would_deny`, with its reason and lane, and
  the connection is admitted. It claims no budget and records no usage.
- A close (revocation, expiry, eviction or key rotation) is counted as
  `close_peer_total{outcome="would_close"}`, and the connection is kept.
- Leases and revocations are still installed and dropped. So the counts are
  the ones enforcement would produce.
- A node over its own byte budget is paced at the cap, not closed.

Observe never refuses. That includes a call its lane cannot take: it is counted
as `would_deny` with reason `overloaded`, and the connection is admitted
without asking Gentility.

### Two lanes

Every authorize call takes one of two lanes.

- The **known lane** is for a key that holds a lease in this relay's cache. It
  is the existing gate: `DERPEX_GENTILITY_MAX_CONCURRENT_REQUESTS`, 64 calls in
  flight. Renewals use it too.
- The **unknown lane** is for any other key. It allows 16 calls in flight
  (`DERPEX_GENTILITY_MAX_UNKNOWN_REQUESTS`), a global bucket of 20 a second
  with a burst of 40 (`DERPEX_GENTILITY_UNKNOWN_RATE=20/40`), and a bucket per
  source of 2 a second with a burst of 10
  (`DERPEX_GENTILITY_UNKNOWN_PER_SOURCE_RATE=2/10`). Rates are written
  `rate/burst`. A source is keyed by its allocation, as the accept limiter
  keys it, in a bounded table.

A call its lane cannot take is refused `admission_overloaded`, and counted
under reason `overloaded`. A refused call spends no token. A flood of made-up keys therefore fills only the unknown
lane. A known node's connection and every renewal never wait behind it.

`derpex_gentility_authorize_total` carries a `lane` label, `known` or
`unknown`, on every outcome. Its label set is fixed, so the series count is
fixed.

### The labels Gentility reads

Gentility's metrics cron reads `/metrics` once a minute and depends on these
words, so they change only with a new contract version:

- `derpex_gentility_authorize_total{outcome,reason,lane}`:
  - `lane`: `known`, `unknown`;
  - `outcome`: `live`, `cached`, `denied`, and under observe `would_deny`;
  - `reason`: `ok` on an admission; on a refusal, `overloaded` (lane shed),
    `no_cached_lease` (Gentility gave no usable record, and nothing is
    cached), and the rest of the fixed set. `no_cached_lease` does not say
    why: a 404 for a key Gentility does not know, a timeout, a 5xx and a
    refused token all count here.
- `derpex_gentility_events_connected`, `derpex_gentility_nearest_lease_expiry_seconds`
  and `derpex_gentility_cache_entries`, unlabelled.

A relay older than v0.2.0 has no `lane`; Gentility counts its series as
`known`.

The exporter's lines are fixed by the test "exports fixed-cardinality
admission metrics through operations" in
`test/derpex/admission/gentility_test.exs`. Gentility's cron test is to take
its `authorize_total` lines from that test verbatim, so that a change there
breaks a test on both sides.

**Clock skew.** A lease whose `issued_ms` is more than
`DERPEX_GENTILITY_MAX_FUTURE_SKEW_MS` (30 s) ahead of the relay's clock fails
verification (`lease_not_yet_valid`). It is counted as
`reason="invalid_record"`, the same as a lease that does not verify, and is not
cached. A relay whose clock runs behind Gentility's therefore shows a rising
`invalid_record` with no change to the signing key.

### A cold relay

A relay that comes back with no unexpired lease in its cache sees every node
as unknown. This happens when its cache is lost, or when it was down longer
than a lease. Its fleet then reconnects through the unknown lane.

From the numbers above:

- The first 40 nodes are admitted on the burst. The rest are refused until
  the bucket refills, then admitted at 20 a second. So N nodes are all in
  within (N − 40) / 20 seconds. For 200 nodes that is 8 s; for 1,000, 48 s.
- Up to 10 computers behind one host address are admitted at once. More than
  10 are refused on their first try. The rest are admitted at 2 a second, so
  all C computers are in within (C − 10) / 2 seconds. For 30 computers that is
  10 s; for 50, 20 s.
- At most 16 calls are in flight at once. A call over that is refused and
  spends no token. So the burst of 40 is taken 16 at a time, and the steady
  20 a second holds only while a Gentility answer takes less than 0.8 s
  (16 / 20). At 50 ms an answer, the 40 take about 0.13 s.

Client backoff comes on top. This was read, not assumed, in Tailscale's client
(`tailscale.com` v1.102.0 from the local Go module cache, not DERPEX's pinned
upstream revision): `wgengine/magicsock/derp.go` backs off after a failed DERP
read with `util/backoff`, which waits n² × 10 ms after the n-th failure in a
row, randomized to 0.5 to 1.5 times that, capped at 5 s. So a refused node
retries quickly at first and every 2.5 to 7.5 s after about 22 failures. A
node can be admitted up to one backoff interval after its token is free.

Once a node is admitted it holds a lease, so its next connection takes the
known lane. Renewals were never in the unknown lane.

**Where it binds.** A cold start is slowed by the lanes only above 40 nodes
reconnecting at once, or above 10 computers behind one address. Below both,
every node is admitted on its first try. Computers on one host share its
address, so the second binds on a host running more than 10 computers; its
computers are then all in within (C − 10) / 2 seconds. Computers on one host
share a bucket. A computer that holds a cached lease takes the known lane and
does not wait in it.

**Telling a cold start from a flood.** Both show the unknown lane shedding
`authorize_total{lane="unknown",reason="overloaded"}`. The answers the lane
does let through differ, and Gentility calls it a cold start only when, in
the same minute, `live` answers outnumber `no_cached_lease` ones:

- In a cold start they are mostly `outcome="live"`: Gentility knows the keys.
  It clears by itself as the lane admits them.
- In a flood they are mostly `outcome="denied",reason="no_cached_lease"`:
  Gentility answers 404 for keys it does not know.

These labels cannot tell a flood from a cold relay whose Gentility is not
answering: both are `no_cached_lease` with few `live`. An alert on them says
"no usable record", not "unknown keys", and is read beside
`events_connected`.
