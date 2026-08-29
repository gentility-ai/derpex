# Gentility deployment profile

DERPEX is deployed as a dedicated OTP release and failure domain. It is not
embedded in the Gentility application VM and is not placed behind an L7 HTTP
proxy or load balancer.

## Fixed topology rules

- Direct TCP 443 with static IPv4 and IPv6 addresses.
- Direct UDP 3478 for STUN.
- Independent single-node regions initially; regional mesh requires a later
  measured justification and ADR.
- DERP-map canary, emergency withdrawal, drain, upgrade, and rollback are
  control-plane operations shared with Gentility.
- Go DERP is not a production dependency or fallback.
- The runtime artifact contains an OTP release and precompiled NIF only. It
  contains no Go/Rust toolchain, upstream checkout, or conformance helper.
- The release includes a module implementing
  `Derpex.Admission.Gentility.ControlPlane`; its authenticated transport is a
  Gentility-owned integration, while leases, revocations, reconciliation, and
  usage batches use DERPEX contract v1.
- Admission cache and usage spool live on persistent encrypted storage with
  mode `0600`. Both are refused at startup if the path is not a regular file or
  is larger than its configured bounds could ever produce, so a replaced or
  symlinked path fails closed instead of being read. Event reconciliation and usage export are mandatory; exhausting
  the bounded spool sheds relay packets rather than losing the billing ledger.
- Global and per-source pre-authentication rate limits plus a per-source open
  connection cap are configured on every public listener. Source tracking is
  LRU-bounded and its operational counters contain no source-IP labels.
- Regional withdrawal calls `Derpex.Drain.begin_drain/2`, removes the region
  from new DERP-map assignments, waits through the hard deadline, and verifies
  zero remaining targeted homes. `Derpex.Drain.cancel/1` is the idempotent
  rollback before upgrade; mesh peers and public probes remain available.
- Public `/healthz` and `/readyz` responses contain status only. `/metrics` and
  `/debug/check` remain nonexistent until `DERPEX_OPERATIONS_TOKEN` is set and
  then require its bearer credential on every request.

## Lease TTL and outage semantics

One number governs how this relay behaves when Gentility is unreachable:
`DERPEX_GENTILITY_MAX_LEASE_MS`, 15 minutes by default.

**It is the worst-case window in which a revoked node can still connect.** A
revocation reaches a relay two ways — pushed on the event stream, and replayed
by reconciliation — but if both are unavailable, the only thing that stops a
revoked node is its cached lease expiring. That is at most one lease lifetime
from the moment the lease was issued. Shortening the TTL shortens that window
and lengthens nothing except how often Gentility is asked to renew.

**An outage longer than one TTL darkens the relay.** Leases for connected nodes
are renewed at 80% of their lifetime, so the clock that matters is the last
*successful* renewal, not the start of the outage. Once a lease expires the node
is closed, and a node with no unexpired cached lease is refused. In practice a
15-minute TTL means: an outage under ~3 minutes is invisible (the next renewal
succeeds), an outage under 15 minutes closes nothing, and beyond that the relay
drains node by node as each lease reaches its expiry — a few minutes early,
spread by jitter.

**Alert on `derpex_gentility_nearest_lease_expiry_seconds`.** Falling toward
zero while `derpex_gentility_authorize_total{outcome="cached"}` climbs is the
signature of an outage about to darken the relay, and it is the only warning
that arrives before connections start dropping. Page on it well before it
reaches zero — a threshold of a third of the TTL gives an on-call responder the
remaining two-thirds to restore Gentility.

**Budgets are per instance, not per fleet.** Every connection and byte
allocation in a lease is enforced by the instance holding it. Gentility must
therefore divide each organization's and node's intended limit by the number of
instances that may serve it, or the fleet's effective limit becomes that number
times the intended one. Adding an instance to a region without redividing
raises every organization's real ceiling.

## Admission lease tuning

The lease controller is configured entirely from the environment. Every value
below applies only when `DERPEX_GENTILITY_ADAPTER` is set, and every one is
validated at boot: an out-of-range value refuses to start the release rather
than silently reverting to its default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DERPEX_GENTILITY_MAX_CACHE_ENTRIES` | `100000` | Hard bound on cached authorization leases. |
| `DERPEX_GENTILITY_MAX_REVOCATIONS` | `10000` | Hard bound on retained revocation records. |
| `DERPEX_GENTILITY_MAX_CONCURRENT_REQUESTS` | `64` | Live authorizations in flight; excess is shed as `admission_overloaded`. |
| `DERPEX_GENTILITY_AUTHORITY_TIMEOUT_MS` | `2000` | Deadline for one live authorization call. |
| `DERPEX_GENTILITY_MAX_LEASE_MS` | `900000` | Longest lease lifetime accepted, and so the worst-case missed-revocation window. |
| `DERPEX_GENTILITY_MAX_FUTURE_SKEW_MS` | `30000` | Clock skew allowed on a lease issue time. It never extends expiry. |
| `DERPEX_GENTILITY_MAX_BYTE_DELAY_MS` | `30000` | Per-node pacing delay above which a connection is closed instead of paced; also the cap on any single pacing wait. |
| `DERPEX_GENTILITY_CACHE_PERSIST_MS` | `5000` | Longest a newly cached lease may go unwritten to disk. |

Size `DERPEX_GENTILITY_MAX_CACHE_ENTRIES` above the number of distinct nodes an
instance expects to serve within one lease lifetime, not above its concurrent
connection count: the cache holds every node that may reconnect during a
Gentility outage. All budgets are per instance and must be divided by the
number of instances in the region.

### Lease renewal

A lease that an established connection is using is re-authorized in the
background once it reaches 80% of its lifetime, through the same authority call
as a fresh admission but marked `renewal: true` and carrying no client info or
source IP. A successful renewal replaces the cached lease in place: budgets and
expiry move forward and the connection is never interrupted. A failed renewal
changes nothing — the existing lease keeps serving — and is retried every
`renewal_retry_ms` (60 s) for as long as the lease has that much life left.

Idle cached leases are not renewed. A node with no connection re-authorizes
naturally the next time it connects, so renewing the whole cache would put the
fleet's reconnection load on Gentility continuously for no benefit.

Renewal traffic shares `DERPEX_GENTILITY_MAX_CONCURRENT_REQUESTS` with live
admissions; a renewal that cannot get a slot is retried rather than queued, so
renewals can never crowd out a connecting node.

A lease's deadline is held on two clocks: the wall clock it was issued against
and the monotonic clock the relay runs on. Whichever says the lifetime is over
closes the lease, so stepping the system clock backwards — by NTP, by a
hypervisor, or by hand — cannot extend a lease past the lifetime Gentility
granted it.

Leases are closed a little before they expire — a jitter of up to 10% of the
lease lifetime, taken out of the lease's own life, never added to it. DERPEX
therefore never serves an expired lease, and a region's leases do not all fall
due in the same millisecond and stampede Gentility on reconnection.

### Regional leases

A lease names the region it was issued for, and DERPEX refuses one that names a
different region than `DERPEX_GENTILITY_REGION_ID` — on live admission, on
cache recovery, on renewal, and on key rotation alike. Budgets are regional
allocations, so honouring a lease from another region would spend that region's
allowance here. Denials are counted as
`derpex_gentility_authorize_total{outcome="denied",reason="wrong_region"}`; a
non-zero rate means a DERP map, a lease issuer, or an instance's region setting
disagree about where this relay is.

### Byte budgets

Node and organization budgets are both token buckets, but they are enforced
differently. A node that runs up its own debt past
`DERPEX_GENTILITY_MAX_BYTE_DELAY_MS` is disconnected: it is the only party
responsible for that debt. An organization's debt only ever paces — one noisy
node must never disconnect the quiet ones that happen to share its
organization. Sibling connections are slowed, up to the same cap so a paced
connection stays responsive, and debt beyond the cap keeps pacing the
reservations that follow rather than accumulating into a stall.

### Cache durability

Writing the cache rewrites the whole file, so lease admissions are debounced:
a change marks the cache dirty and the file is written at most once per
`DERPEX_GENTILITY_CACHE_PERSIST_MS`, and again when the controller shuts down.
A burst of reconnections therefore costs one write rather than one per node.

Revocations and reconciliation batches are never deferred — they are the
security-relevant writes, and each flushes the file synchronously before the
call returns, so a revocation is durable by the time Gentility is told it was
applied. Verification-key rotation flushes when its sweep completes.

The write itself runs in a dedicated writer process, so the controller pays
only for encoding the snapshot, never for the disk. At most one write is in
flight and queued snapshots replace one another, so lease churn cannot build a
backlog of writes.

Verification-key rotation re-verifies every cached record, one signature check
each, in bounded chunks between other messages. A rotation therefore is not
atomic: records signed only by a retired key are dropped and their connections
closed as the sweep reaches them, so a large cache sheds admissions over a
brief window rather than all at once. Leases signed by a key that is still
published are unaffected.

Worst case, an unclean crash (SIGKILL, power loss, or a VM halt that skips
shutdown) loses the leases admitted in the last `DERPEX_GENTILITY_CACHE_PERSIST_MS`
and nothing else. Those nodes simply re-authorize against Gentility on their
next connection; a lost lease can never admit a node that should be denied. No
revocation is ever lost this way. The cost of a longer window is a slightly
larger set of nodes that must reach Gentility after a crash that coincides with
a control-plane outage; lower it only if that combination is a real concern.

### Cache eviction

The cache never sacrifices an established peer to admit a new one. When it is
at its bound, a new lease evicts, in order:

1. an expired entry, claimed or not, because an expired lease must close anyway;
2. otherwise the soonest-expiring entry that no connection is claiming, ties
   broken by node key.

Both orders are maintained incrementally, so admitting a lease, claiming a
connection, and releasing one cost the same whether the cache holds ten leases
or a hundred thousand.

If every entry holds a valid lease with a live claim, the *new* admission is
rejected with `cache_full` and the counter behind
`derpex_gentility_cache_full` increments. Sustained growth in that counter
means the cache bound is below the instance's working set: raise
`DERPEX_GENTILITY_MAX_CACHE_ENTRIES` or reduce the nodes homed on the instance.

## Revocation delivery

Revocations reach every relay two ways: a live stream, and a reconciliation
pass that replays what a disconnected relay missed. A pass is paged — DERPEX
asks for a page, applies it, and asks again with the position it was given
until the control plane answers with no position — so a backlog of tens of
thousands of records never depends on one oversized response. A pass is bounded
by page count as well as by records and bytes per page, so a control plane that
never finishes a pass is abandoned and retried instead of looping.

A revocation closes a node two ways at once, because a connection is claimed
before the router knows about it: the router is asked to close the peer, and
every connection holding a claim on that node key is told to close directly.
A revocation that lands in the moment between the two therefore still lands.

Gentility prunes revocations older than `DERPEX_GENTILITY_MAX_LEASE_MS`. Every
lease such a record could still deny has expired by then, which is what keeps
reconciliation bounded: the window that must be replayed is exactly one maximum
lease lifetime.

## Admission metrics

Every admission decision the controller answers is counted under a fixed label
set — no node, organization, or source identity ever reaches a label:

- `derpex_gentility_authorize_total{outcome,reason}` — `outcome` is `live`,
  `cached`, or `denied`; denials carry one of a fixed reason set
  (`no_cached_lease`, `lease_revoked`, `cache_full`, `stale_lease`,
  `wrong_region`, `invalid_record`, `overloaded`, `unavailable`, `other`).
  A rising `cached` share means Gentility is unreachable and the relay is
  running on cached leases.
- `derpex_gentility_close_peer_total{cause}` — `expiry`, `revocation`,
  `eviction`, or `key_rotation`.
- `derpex_gentility_nearest_lease_expiry_seconds` — how long until the next
  cached lease is closed. **Alert on this.** It falling toward zero across the
  fleet while `authorize_total{outcome="cached"}` climbs is the signature of a
  Gentility outage that is about to darken the relay. The series is absent when
  no lease is cached.
- `derpex_gentility_cache_load_error` / `derpex_gentility_cache_persist_error` —
  1 while the durable cache could not be read at boot or last failed to write.
- `derpex_gentility_renewals_in_flight`, `derpex_gentility_cache_full`.
- `derpex_gentility_byte_pacing_capped_total` — reservations whose pacing wait
  hit `DERPEX_GENTILITY_MAX_BYTE_DELAY_MS`. A rising count with no closes is an
  organization sitting over its byte allocation while its members stay
  connected.
- `derpex_gentility_close_peer_failed_total` — closes the router could not
  complete. A close that fails is isolated and counted rather than costing the
  batch; a persistent count means peers may outlive their revocation.

Warnings are rate limited per kind (one per minute per controller) so a
persistent condition cannot flood the log: authority unavailable and serving
cached, revocation applied, eviction, cache full, key rotation, and cache
load/write failures. The counters behind them stay exact regardless.

## Usage export

Each fixed window is exported as one or more batches with the same window
bounds. A batch is bounded twice: at most 10 000 sender attributions, and at
most 8 MiB on the wire. The window is ordered once and cut into batches of
10 000; a cut still too large for the wire — long identities make that
possible well below 10 000 entries — is bisected and retried until each half
encodes. A busier or wider window therefore produces more batches, never a
loss.

Only a single row that cannot encode on its own is discarded. It is logged,
counted in `derpex_gentility_usage_dropped_rows`, and deleted, because a row
that can never be encoded would otherwise block the spool and shed every
relayed packet behind it. Every other row sharing its window is still
exported. Any increase in that counter is an accounting loss and must alert.

A spool file the relay cannot read — corrupt, truncated, replaced, or over its
configured bounds — is moved aside as `<path>.corrupt-<timestamp>`, logged, and
flagged by `derpex_gentility_usage_spool_load_error`; accounting then restarts
empty. The ledger for that window is lost and the kept file is what to recover
from, but a relay never refuses to boot over one unreadable file.

`derpex_gentility_usage_dropped_rows` counts since the usage worker started, so
a restart resets it to zero. Alert on an increase rather than an absolute
value, and read a reset as a restart, not as recovery. Spooled batches survive
a restart; the counter does not.

## Milestone 0 launch inputs

The following values must be jointly fixed before Milestone 0 exits:

- initial region IDs, names, providers, and reference instance types;
- concurrent connections per instance and region;
- aggregate and per-connection throughput;
- expected maximum sustained DERP share of overlay traffic;
- p95 and p99 relay latency;
- maximum queue age and drop rate;
- idle and active memory per connection;
- overload and admission-shedding behavior;
- expected regional bandwidth cost;
- metadata retention and billing aggregation windows; and
- alert thresholds and on-call routing.

This file becomes the executable production runbook as those decisions land.
