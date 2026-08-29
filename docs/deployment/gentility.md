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
  mode `0600`. Event reconciliation and usage export are mandatory; exhausting
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
| `DERPEX_GENTILITY_MAX_BYTE_DELAY_MS` | `30000` | Pacing delay above which a connection is closed instead of paced. |

Size `DERPEX_GENTILITY_MAX_CACHE_ENTRIES` above the number of distinct nodes an
instance expects to serve within one lease lifetime, not above its concurrent
connection count: the cache holds every node that may reconnect during a
Gentility outage. All budgets are per instance and must be divided by the
number of instances in the region.

### Cache eviction

The cache never sacrifices an established peer to admit a new one. When it is
at its bound, a new lease evicts, in order:

1. an expired entry, claimed or not, because an expired lease must close anyway;
2. otherwise the soonest-expiring entry that no connection is claiming, ties
   broken by least recently used.

If every entry holds a valid lease with a live claim, the *new* admission is
rejected with `cache_full` and the counter behind
`derpex_gentility_cache_full` increments. Sustained growth in that counter
means the cache bound is below the instance's working set: raise
`DERPEX_GENTILITY_MAX_CACHE_ENTRIES` or reduce the nodes homed on the instance.

## Usage export

Each fixed window is exported as one or more batches of at most 10 000 sender
attributions; a busier window simply produces more batches with the same
window bounds. A batch the contract cannot encode is logged, counted in
`derpex_gentility_usage_dropped_rows`, and its rows are deleted, because a
window that can never be encoded would otherwise block the spool and shed every
relayed packet behind it. Any increase in that counter is an accounting loss
and must alert.

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
