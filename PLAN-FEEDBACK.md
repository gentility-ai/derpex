# DERPEX Plan — Gentility Suitability Feedback

Date: 2026-08-28

Review target: [`PLAN.md`](PLAN.md)

## Verdict

Protocol-wise, the DERPEX plan is excellent. As the production relay for
Gentility's overlay, it is not yet complete, and some priorities are in the
wrong order.

| Dimension | Verdict |
| --- | --- |
| Protocol correctness | Excellent |
| Test/oracle strategy | Excellent |
| BEAM architecture | Strong, with one queue correction |
| Gentility authorization/accounting | Missing |
| Production topology and SLOs | Missing |
| Delivery scope | Overbuilt in places, underbuilt in others |
| Suitable as overlay critical path today | No |
| Suitable after revision | Yes |

## What is particularly strong

- The Go and Rust baselines were both current as of 2026-08-27.
- "Pinned Go behavior wins" is the right compatibility rule.
- The complete upstream test inventory, unchanged Go clients, differential
  oracle, malformed-input properties and soak tests are unusually good.
- The fast path avoids a global GenServer and keeps crypto out of the packet
  path.
- Reader/Outbox/Writer separation is the right shape for isolating slow TLS
  clients.
- The Rust boundary is admirably small.
- Explicit clocks, frame ordering, duplicate-key behavior, mesh convergence
  and binary-retention profiling all address real failure modes.
- Compatibility exceptions are stated honestly rather than hidden.

If the objective is "write a defensible Elixir implementation of
`cmd/derper`," this is an excellent plan.

## The main missing piece: Gentility's relay contract

DERPEX currently clones Go's admission model: node public key plus source IP
goes to a Boolean allow/deny endpoint. Upstream itself has a TODO for
bandwidth policy.

Gentility needs more:

- Resolve the node key to an active Gentility node.
- Attribute the connection to organization, owner kind and deployment.
- Apply per-node and per-org connection and bandwidth limits.
- Export usage for cost/accounting without high-cardinality Prometheus
  labels.
- Close existing connections promptly when a node is revoked.
- Define what happens when Gentility is unavailable.

A simple fail-closed HTTP check makes DERPEX dependent on the mothership for
every reconnection—the exact coupling it is meant to remove. Fail-open is
unacceptable for revoked nodes.

Design a bounded admission lease:

1. Gentility authorizes a node key and returns identity, limits, revision and
   lease expiry.
2. DERPEX caches that authorization locally.
3. During an outage, an unexpired lease permits reconnection.
4. Revocation is pushed to every DERPEX instance and actively invokes
   `ClosePeer`.
5. Lease expiry bounds the worst-case missed-revocation interval.
6. Reconciliation repairs missed revocation messages.

This should be a first-class `Derpex.Admission.Gentility` contract, not
deployment glue.

## Reorder the milestones for safe deployment

Several production essentials arrive surprisingly late:

- TLS/WebSocket: Milestone 6.
- Admission and rate limiting: Milestone 7.
- STUN: Milestone 8.
- Certificate automation: Milestone 9.
- Persistent identity, graceful shutdown and decommissioning: Milestone 10.
- Capacity limits: Milestone 11, with numeric targets explicitly deferred.

The Milestone 3 "vertical slice" is therefore a protocol demonstration, not
something Gentility can safely deploy publicly.

For a Gentility MVP, bring forward:

- Native TLS.
- One supported certificate-renewal or hot-reload path.
- Gentility admission leases and revocation.
- Connection and byte limits.
- Core metrics.
- STUN and external probing.
- Persistent identity.
- Graceful drain/restart.
- Fixed capacity targets and overload behavior.

Regional mesh, complete HTTP parity and ancillary CLI behavior can follow.

## Make the bounded queue structurally bounded

The plan says queues must not become unbounded mailboxes, but initially
proposes ordinary `send/2` into the Outbox.

A BEAM mailbox is unbounded. "The Outbox never blocks" does not guarantee
that aggregate senders cannot outpace its reductions. A Milestone 1 spike can
prove a workload-specific result, but not a structural bound.

Make the proposed `:atomics` admission plus fixed ETS ring—or another
genuinely fixed-capacity structure—the default design. Senders should:

- CAS-reserve a slot.
- Write the packet reference into a bounded ring.
- Coalesce a single wake-up to the writer/outbox.
- Drop or replace without first entering an unbounded mailbox.

That provides the same fundamental property as Go's non-blocking bounded
channel rather than depending on scheduler throughput.

## DERP may be a heavier data path for Gentility

DERP is normally a low-bandwidth fallback. Gentility may carry through it:

- Database sessions and result sets.
- Browser preview assets.
- LLM streaming.
- Build control and replication.
- Potentially egress routed through a customer exit.

Build sandboxes and corporate servers are also precisely the environments
most likely to block direct UDP. Gentility's relay rate may therefore be
materially higher than a normal tailnet.

Numeric targets cannot remain deferred. Before implementation, define at
least:

- Concurrent connections per node and region.
- Aggregate and per-connection throughput.
- Maximum sustained DERP share of overlay traffic.
- p95/p99 relay latency.
- Maximum queue age and drop rate.
- Memory per idle and active connection.
- Graceful overload behavior.
- Expected regional bandwidth cost.

Tailscale now recommends Peer Relays for higher-throughput
restricted-network paths, with DERP retained as fallback. See [Tailscale Peer
Relays](https://tailscale.com/docs/features/peer-relay). Headscale's current
policy implementation supports `tailscale.com/cap/relay`, so evaluate this
for mothership/build-box and mothership/Connector traffic.

A sensible division is:

- DERPEX: universally reachable rendezvous and last-resort relay.
- Gentility peer relays: higher-throughput relay where direct UDP fails but a
  suitable UDP relay is reachable.
- Direct WireGuard: preferred.

## Add a regional deployment design

The plan implements regional mesh well, but says little about the actual
fleet. Add a Gentility deployment profile covering:

- Initial regions and why.
- Stable region IDs and node names.
- Static IPv4 and IPv6 addresses.
- Dedicated port 443, not behind Caddy or an HTTP load balancer.
- UDP 3478 exposure.
- Network-level DDoS protection.
- Full-mesh key distribution and rotation if mesh is used.
- DERP-map publication, canarying and emergency withdrawal.
- External probes from multiple networks.
- Upgrade, drain and rollback sequence.
- Alert thresholds and on-call routing.

Tailscale's self-hosting guidance recommends avoiding multiple nodes inside
one region unless needed; two one-node regions in the same location can be
simpler than a regional mesh, particularly for non-mobile clients. The
overlay should probably begin with several single-node regions and add
intra-region mesh only when availability or connection economics justify it.

DERPEX must run as a dedicated OTP release with separate resource limits and
failure domain. Do not embed it in the Gentility application VM or colocate it
such that a mothership/head failure also takes out the relay.

## Reconsider the `FrameRestarting` exception

The plan deliberately never emits `FrameRestarting` because the pinned Go
server does not. That is correct for default compatibility, but the client
already understands the frame.

For controlled rolling deployments, support it behind an explicit drain
command:

- Stop admitting new home connections.
- Send restart notices with jitter.
- Wait for connections to migrate.
- Close remaining connections at the deadline.

It can remain disabled by default and be recorded as a Gentility extension
rather than baseline behavior.

## Scope to defer from the Gentility MVP

Gentility does not initially need all of `cmd/derper`:

- Bootstrap DNS, if every DERP-map node carries explicit IPv4 and IPv6.
- Homepage modes and robots parity.
- GCP EAB certificate parity.
- Raw-IP ACME certificates.
- Exact compatibility for every CLI flag.
- Setec flag compatibility.
- Experimental ACE.
- Public-package-oriented precompiled NIF delivery across all four developer
  targets.

For an internal service, a reproducible multi-architecture OCI image is
enough initially.

The planned release sequence also generates and commits the checksum manifest
after the release tag. That risks the tagged source and published artifacts
describing different states. If public library distribution remains a goal,
restructure that sequence before implementing it. Prefer generating the
artifacts and manifest before the immutable release tag, or make the manifest
a versioned release artifact with an explicitly reproducible source-package
process.

## Add privacy and abuse controls

DERP cannot read payloads, but it sees metadata: node keys, source IPs,
destination keys, timing, packet sizes and connection outcomes.

The plan should state:

- Which metadata is retained.
- Retention periods.
- Whether per-peer traffic relationships are ever recorded.
- How org usage is aggregated for billing.
- That encrypted payloads are never logged.
- Debug endpoint authorization.
- Core/ERTS crash-dump handling.
- Per-IP handshake and connection caps.
- Admission-controller cache limits.
- Response to volumetric TCP/TLS and STUN attacks.

STUN should not be application-rate-limited in a way that breaks netcheck, so
volumetric protection belongs primarily at the host/provider network
boundary.

## Keep Go DERP as the production path during development

A standalone `cmd/derper` already provides an independently deployed relay on
Gentility infrastructure. DERPEX is not required to decouple DERP from
Headscale.

Keep the embedded or standalone Go DERP as the production path while DERPEX
is built and proven. DERPEX should earn replacement through:

- Better Gentility admission and revocation.
- Better observability and operability.
- Comparable capacity and latency.
- Safe regional deployment.
- Repeated mixed Go/tsnet interoperability.
- Canary operation beside Go.

Do not make the overlay launch wait for all DERPEX milestones.

## Recommended Gentility-ready definition of done

A first Gentility-capable release needs:

- Native TLS DERP and standard Go/tsnet interoperability.
- Truly bounded packet and control queues.
- Duplicate and `PeerGone` correctness.
- STUN and probe endpoints.
- Gentility admission leases, org attribution and active revocation.
- Per-node and per-org connection and byte limits.
- Persistent identity and certificate renewal/reload.
- Graceful drain, restart and rollback.
- Metrics, external probes, dashboards and alerts.
- Declared capacity and SLOs.
- At least two independent regions.
- A canary migration from Go DERP.
- Privacy and abuse policies.

Regional mesh, WebSocket parity, ancillary HTTP, comprehensive CLI parity and
public package distribution can then extend it.

## Bottom line

Preserve most of the implementation plan, but change its definition of
success from "complete clone of pinned `cmd/derper`" to "correct DERP core
plus Gentility's authorization, availability, accounting and operational
contract."

Without that addition, the plan covers virtually all DERP protocol needs but
not all Gentility relay needs.
