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
