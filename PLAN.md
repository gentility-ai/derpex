# DERPEX implementation plan

Status: approved integrated direction, implementation started 2026-08-28

DERPEX is an Elixir implementation of Tailscale's DERP server. The target is
observable compatibility with the pinned Go implementation, including the
tested `cmd/derper` surface. The packet relay remains on the BEAM. A small Rust
NIF supplies only the NaCl-compatible key and box operations required during
the DERP handshake.

DERPEX is also the relay implementation for Gentility's new overlay product;
there is no existing Go relay deployment to preserve or replace. DERPEX and
Gentility's authorization, revocation, accounting, and regional-control
surfaces are developed together and share one launch gate. Go code exists only
in development and isolated conformance CI. A deployed DERPEX artifact contains
an OTP release and its precompiled crypto NIF, never a Go or Rust toolchain.

## 1. Reference baseline

The initial compatibility baseline is immutable until an explicit upstream
upgrade is undertaken:

| Reference | Repository | Commit | Role |
| --- | --- | --- | --- |
| Go | `https://github.com/tailscale/tailscale` | `1e69418c298b680562a2fecd7020f7f58d17d166` | Normative behavior oracle |
| Rust | `https://github.com/tailscale/tailscale-rs` | `1a969ad5dd753aa3b2bbb91499ed64cc6baef621` | Independent client and crypto cross-check |

Local development may use `../tailscale` and `../tailscale-rs`, but CI and the
test harness must resolve repositories from a committed lock file rather than
depending on absolute local paths. An environment override may point at an
already-present clean checkout, provided its commit matches the lock.

Upstream commits never advance automatically. An upgrade changes the lock,
regenerates the test inventory, updates the compatibility matrix, and lands as
a dedicated reviewable change.

## 2. Compatibility contract

### 2.1 Normative rule

For the same externally supplied configuration, connection sequence, bytes,
and relevant clock events, DERPEX must produce the same observable protocol
events, connection decisions, HTTP responses, and routing outcomes as the
pinned Go implementation.

Comparison is semantic where bytes are intentionally nondeterministic. Random
nonces, generated identities, certificate signatures, connection numbers,
timestamps, keepalive jitter, log wording, and unordered concurrent events are
normalized before differential comparison.

### 2.2 In scope

- DERP v2 framing, limits, handshake, and NaCl box compatibility.
- Native HTTP/1.1 DERP upgrade and TLS metacert fast-start.
- WebSocket DERP using the `derp` subprotocol with compression disabled.
- Single-server packet relay and source attribution.
- Duplicate node-key behavior.
- Bounded per-client queues, drop policy, stalled-client isolation, and write
  timeouts.
- Keepalive, ping/pong, preferred-server notes, unknown frames, and malformed
  frame behavior.
- `PeerGone`, including disco-only unknown-destination notification and rate
  limiting.
- Regional mesh watching, presence updates, forwarding, reconnect behavior,
  multi-forwarders, and privileged `ClosePeer`.
- Per-client receive rate limiting and live rate configuration reload.
- Admission by disallowed app name, local tailscaled, and HTTP admission
  controller, including fail-open behavior.
- TLS metacert and the certificate modes exercised by `cmd/derper` tests.
- STUN, bootstrap DNS, latency/probe endpoints, captive-portal endpoint,
  homepage/robots behavior, metrics, and tested debug endpoints.
- Tested CLI, key persistence, configuration, signal, and shutdown behavior.
- Experimental ACE behavior if the pinned binary exposes it; it is scheduled
  after all stable tested surfaces.

### 2.3 Not required to be implementation-identical

Go allocation counts, Go hash-trie internals, goroutine layout, expvar object
types, and the exact HyperLogLog implementation are not portable requirements.
The externally visible behavior and metrics they protect remain requirements.
The separate Linux XDP package is not part of the current `cmd/derper` request
path; its tests are recorded as implementation-specific unless later evidence
shows an observable server requirement.

ACME (RFC 8555) is **implemented**, not excepted. `DERPEX_CERT_MODE=letsencrypt`
and `DERPEX_CERT_MODE=gcp` obtain certificates through `Derpex.ACME`: ES256 JWS,
an optional external account binding for GCP, `newOrder` with one DNS or IP
identifier and the RFC 8555 profiles extension, HTTP-01 answered on the
plaintext port, a single-SAN certificate request, finalize and chain download.
No published Hex ACME library carries IP identifiers or the profiles extension,
and adopting one would have widened the release's twelve-application runtime
closure, so the client is written against OTP alone; ADR 0004 records the
survey and the decision.

Two consequences are worth stating rather than discovering:

- An ACME mode requires `DERPEX_HTTP_PORT`. A certificate authority validates
  HTTP-01 by connecting to port 80 at the identifier being validated, so the
  configuration is refused at boot without a plaintext listener rather than
  failing on the first order.
- A listen socket binds one certificate and cannot be told about a renewal, so
  the certificate manager publishes each issuance into the same
  `:persistent_term` snapshot a rotated file-backed certificate uses, and
  `Derpex.Listener.Transports.SSL` reads it per connection. A renewed
  certificate therefore reaches hellos with and without SNI alike.

`DERPEX_IP_CERT_ISSUER=self` remains as a local alternative: persistent
self-signed per-IP certificates that contact no certificate authority.

The following are recorded as explicit, user-approved compatibility exceptions
so they are not implemented by accident:

- `FrameHealth` (0x14) and `FrameRestarting` (0x15) are defined in the pinned
  `derp.go` but never emitted by the pinned server. DERPEX does not emit them in
  its baseline profile. The Gentility profile may emit `FrameRestarting` only
  during an explicitly requested graceful drain, as described in Section 3.6.
- The pinned Go `http.Server` negotiates HTTP/2 via ALPN on the TLS listener,
  so non-DERP endpoints are reachable over h2. DERPEX advertises `http/1.1`
  only. The DERP upgrade path is HTTP/1.1 in both implementations.
- `--secrets-url`, `--secrets-path-prefix`, and `--secrets-cache-dir` (setec
  mesh-key retrieval) are accepted for flag-compatibility and rejected with a
  clear error. No setec client is implemented.
- `/debug/set-mutex-profile-fraction` is Go-runtime-specific and is
  `implementation-specific` in the inventory.
- The pinned Go `recvClientKey` accepts an unauthenticated `ClientInfo` frame
  of up to 256 KiB. DERPEX caps it at 16 KiB, because a real `ClientInfo`
  payload is under 200 bytes and the frame is read before the peer is
  authenticated. A conforming client is never affected; an oversize frame is
  closed at its header instead of after its body.
- Section 3.3 requires that a sender is never suspended by a destination's
  queue. DERPEX suspends one for up to about four milliseconds when that
  destination's outbox ring lock is held for that long, because Go's channel
  send never loses a packet the queue has room for and DERPEX's ETS lock,
  unlike a channel, can be held across a scheduler preemption. The budget is
  wall-clock bounded, the naps inside it are counted as
  `derp_ring_producer_naps`, exceeding it is a counted tail drop, and callers
  that must not sleep for one destination — the router and the drain
  coordinator — enqueue with `wait: false`. See ADR 0001.

### 2.4 Compatibility precedence

When documentation, the Rust client, and Go behavior disagree:

1. Pinned Go executable behavior wins.
2. Pinned Go tests clarify intent.
3. Go source comments guide unspecified cases.
4. The Rust implementation is an interoperability signal, not an oracle.

### 2.5 Baseline and Gentility profiles

DERPEX has one codebase with two explicitly tested behavioral profiles:

- The **baseline profile** implements the pinned Go behavior and is used by
  differential and upstream compatibility gates. Gentility extensions are
  disabled so they cannot mask a protocol deviation.
- The **Gentility profile** preserves the DERP wire contract while adding
  leased authorization, active revocation, organization attribution, product
  limits, usage export, and controlled restart notices.

The Gentility launch gate requires both profiles to pass. Product extensions
do not weaken, normalize away, or replace any baseline compatibility test.

## 3. Architectural decisions

### 3.1 Process and data flow

```text
TCP/TLS listener
    |
    v
HTTP/1 + transport handler (one reader per connection)
    |-- handshake ----------> Rust crypto resource
    |-- rare control -------> Router GenServer
    `-- packet -------------> ETS route lookup
                                  |
                                  v
                         destination Outbox
                         (bounded queues)
                                  |
                                  v
                           socket Writer
                      (TCP/TLS/WebSocket adapter)
```

The router serializes registrations and rare topology changes only. A normal
packet must not traverse a global GenServer.

### 3.2 Proposed OTP components

- `Derpex.Application`: root supervision tree.
- `Derpex.ListenerSupervisor`: native, TLS, HTTP, and STUN listeners.
- `Derpex.Transport`: common byte-stream behavior.
- `Derpex.Transport.Native`: TCP/TLS adapter.
- `Derpex.Transport.WebSocket`: WebSocket binary-stream adapter.
- `Derpex.HTTP1`: bounded incremental request/header parser and endpoint router.
- `Derpex.Frame`: streaming DERP frame decoder and iodata encoder.
- `Derpex.ClientInfo` and `Derpex.ServerInfo`: Go-compatible JSON mapping.
- `Derpex.Crypto`: Elixir facade and behavior.
- `Derpex.Crypto.Native`: Rustler-backed identity resource and NaCl box calls.
- `Derpex.Connection`: handshake and inbound-frame state machine.
- `Derpex.Router`: registration, duplicates, mesh routes, and reverse-path
  bookkeeping.
- `Derpex.RouteTable`: protected ETS tables and common lookup operations.
- `Derpex.Outbox`: per-connection coordinator around fixed-capacity
  ordinary/disco/control rings. Packet references never enter its mailbox;
  senders publish directly to bounded storage and coalesce a single wake-up.
- `Derpex.Writer`: per-connection socket-writer process. Pulls one item at a
  time from the Outbox and is the sole process that writes bytes.
- `Derpex.Clock`: injectable clock behavior (`now`, `send_after`, timers) used
  by every timeout, keepalive, and rate limiter so tests can drive time
  deterministically. Mirrors Go's `tstime.Clock` / `tstest.Clock`.
- `Derpex.Mesh.Client`: outbound DERP client used for server meshing.
- `Derpex.Mesh.Supervisor`: mesh connection lifecycle and reconnects.
- `Derpex.RateLimiter`: accept, receive-byte, and peer-gone token buckets.
- `Derpex.Admission`: behavior for configured admission checks.
- `Derpex.Admission.Gentility`: authorization leases, bounded local cache,
  revocation stream, reconciliation, and outage policy.
- `Derpex.Quota`: per-node and per-organization connection/byte budgets that
  require no synchronous mothership call on the packet path.
- `Derpex.Usage`: fixed-window organization accounting with a bounded durable
  export spool and idempotent delivery.
- `Derpex.Metrics`: counters, gauges, histograms, and Prometheus rendering.
- `Derpex.STUN`: UDP STUN server.
- `Derpex.Certificates`: manual, ACME, IP certificate, and metacert handling.
- `Derpex.Config` and `Derpex.CLI`: persistent identity and executable surface.

Names may change during implementation, but boundaries and ownership should
not change without an architecture decision record.

### 3.3 Connection ownership invariants

- Exactly one process parses inbound bytes for a connection.
- Exactly one process writes bytes for a connection.
- A connection is three processes: reader, Outbox (queue owner), Writer
  (socket writer). The Outbox coordinates fixed-capacity storage, so a stalled
  socket write lands in a process that owns nothing else and packet references
  cannot accumulate in an unbounded mailbox.
- Senders enqueue without blocking. Go's `sendPkt` is a non-blocking channel
  send with a drop-head fallback; DERPEX must preserve that a sender's reader
  is never suspended by a destination's queue or socket.
- No timeout, keepalive, or limiter reads wall-clock time directly; all go
  through `Derpex.Clock`.
- All outbound frames, including handshake completion, packets, pongs,
  presence events, and keepalives, have an explicitly tested ordering.
- A slow writer cannot block any other client's reader or writer.
- Queue capacity is explicit and cannot be replaced by an unbounded process
  mailbox.
- Disconnect cleanup is idempotent and removes routes, watches, timers, and
  queued payload references.
- Local routes win over mesh forwarders.
- A forwarded packet is delivered locally or dropped; it is never forwarded a
  second time.

### 3.4 Packet representation

Packets stay as reference-counted binaries. Parsing uses binary pattern
matching and sub-binaries. Sending uses iodata such as
`[frame_header, source_key, payload]`. No NIF call occurs on the packet path.

The router's fast-path table maps a 32-byte node public key to the currently
active local outbox. Duplicate and mesh misses fall back to serialized router
state. The design must be benchmarked before sharding ETS or introducing more
route tables.

### 3.5 Queue semantics

Each client has separate ordinary and disco queues, each defaulting to depth
32. When a data queue is full, fresher packets replace older queued packets in
the same class, matching the intent and observable counters of the Go
drop-head loop. A tail drop remains possible only where concurrent admission
makes replacement impossible.

Control traffic is bounded independently:

- At most one unsent pong is retained.
- Mesh update wakeups are coalesced while retaining the underlying state
  changes.
- Peer-gone and shutdown control cannot be starved indefinitely by packet
  traffic.

The default enqueue mechanism is structurally bounded. Each queue has exactly
its configured number of packet-bearing slots in an ETS ring (or an equivalently
fixed-capacity structure), with sequence/admission state in `:atomics`. Senders
reserve and publish without waiting for the destination process, replace or
drop according to the queue policy, and coalesce at most one atom-only wake-up.
The Writer drains published slots in sequence. Reserved-but-not-yet-published
slots, stale producers, wraparound, disconnect, and concurrent replacement are
part of the Milestone 1 proof and ADR. A design that places packet references in
an ordinary process mailbox is not an acceptable fallback.

Write timeouts (two seconds regular, thirty seconds privileged) are enforced
per transport and tested per transport, because the mechanisms differ:
`gen_tcp` uses `send_timeout` with `send_timeout_close`; `:ssl.send` needs an
explicit timer around the call; the WebSocket adapter wraps whichever
underlying socket it rides on. In every case only the timed-out connection is
closed.

### 3.6 Gentility relay contract and deployment profile

Gentility authorization is a versioned product protocol developed in concert
with DERPEX. An authorization response binds the DERP node key to a Gentility
node, organization, owner kind, deployment, policy revision, regional quota
allocation, and explicit lease expiry. The response is authenticated so a
cached lease can be validated locally. The precise wire encoding and signing
scheme are frozen by an ADR before Milestone 3 exits.

The outage and revocation contract is fail-bounded rather than simply
fail-open or fail-closed:

- an unexpired cached lease permits connection or reconnection without a live
  mothership request;
- an unknown or expired node is denied while Gentility is unavailable;
- an existing connection is closed no later than lease expiry;
- revocations are pushed to every DERPEX instance and disconnect all local
  duplicates immediately;
- periodic revision reconciliation repairs a missed push; and
- cache size, durable state, clock skew, key rotation, and outage behavior are
  explicitly bounded and tested.

Global organization limits must not introduce a synchronous control-plane call
on the packet path. Gentility allocates versioned regional or instance budgets;
DERPEX enforces those budgets locally and reports consumption in fixed windows.
Usage batches are idempotent, durably and boundedly spooled during an outage,
and contain the minimum organization/node attribution required for accounting.
Prometheus metrics use bounded labels and are not the billing ledger.

The initial fleet consists of independent single-node regions. Each instance is
a dedicated OTP release and failure domain with static IPv4/IPv6, direct TCP
443, UDP 3478, provider/network DDoS controls, and no Caddy, L7 HTTP load
balancer, or Gentility application VM in front of it. DERP-map publication,
canarying, emergency withdrawal, external multi-network probes, drain, upgrade,
rollback, alerts, and on-call ownership are defined before launch. Regional
mesh is added only when measured availability or connection economics justify
it.

An explicit Gentility drain stops new home connections, optionally emits
`FrameRestarting` with bounded jitter, waits for migration, and closes remaining
connections at a deadline. This extension is disabled in the baseline profile.
Direct WireGuard remains preferred; an ADR evaluates Tailscale Peer Relays for
high-throughput restricted-network paths while DERPEX remains the universally
reachable rendezvous and last-resort relay.

### 3.7 Native boundary

The Rust crate is intentionally small and depends directly on RustCrypto's
`crypto_box`, not on the full `tailscale-rs` workspace. Two alternatives were
considered and rejected: `enacl` (libsodium) would remove all custom `unsafe`
but adds a system library dependency that the Rust toolchain already required
for CI does not; `ts_elixir` in `tailscale-rs` already provides Rustler
bindings but is experimental and pulls in the entire client runtime. The crate
exposes:

- identity generation and loading;
- public-key derivation;
- `seal_to(peer_public, plaintext) -> nonce <> ciphertext`;
- `open_from(peer_public, nonce <> ciphertext)`.

The secret key lives in a zeroizing Rustler resource. All arguments are length
checked before conversion. Decryption of untrusted, potentially large client
info uses a dirty CPU scheduler. Panics must not cross the NIF boundary.
Cross-language vectors cover Go-to-Rust and Rust-to-Go encryption.

Distribution uses `rustler_precompiled`. A source-package or OTP-release build
downloads a checksum-verified NIF archive and never invokes `cargo` or `rustc`;
the primary OCI artifact already contains ERTS and the NIF, so its deployer
needs no language toolchain at all. `rustler` remains an optional source-build
dependency, enabled explicitly with `DERPEX_BUILD=1` for local NIF development,
CI lint/tests, and unsupported-target experimentation. The source package keeps
the Rust crate so that this escape hatch remains available.

The initial precompiled target matrix follows the proven `ex_monty` pattern:
`aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-gnu`. Each supported
target is release-blocking. Additional targets, including musl, are added before
DERPEX claims support for them; missing or invalid artifacts fail with an
actionable error rather than silently attempting a local Rust build.
The artifact filename's NIF ABI is the oldest ABI supported by the chosen OTP
matrix and is declared once for both the loader and release workflow so the two
cannot drift.

Moving framing, routing, sockets, queues, or mesh logic into a NIF requires a
profile demonstrating a material bottleneck and a separate architecture
decision. If the entire data plane ever becomes native, a crash-isolated port
or sidecar is preferred over a large stateful NIF.

## 4. Repository and tooling shape

The intended layout is:

```text
.
|-- .github/workflows/
|   |-- ci.yml
|   `-- release.yml
|-- Dockerfile
|-- .dockerignore
|-- lib/derpex/
|-- native/derpex_crypto/
|-- checksum-Elixir.Derpex.Crypto.Native.exs
|-- test/
|   |-- support/
|   |-- unit/
|   |-- property/
|   `-- system/
|-- interop/
|   |-- upstream.lock
|   |-- COVERAGE.md
|   |-- go/
|   |-- rust/
|   `-- fixtures/
|-- bench/
|-- docs/adr/
|-- docs/deployment/gentility.md
|-- rel/
|-- scripts/
|   |-- release.exs
|   `-- verify_runtime.exs
|-- PLAN.md
`-- README.md
```

`interop/upstream.lock` pins the Go and Rust repository commits, the Go
toolchain version required by the pinned `go.mod`, and the Rust toolchain
from the pinned `rust-toolchain.toml`. `docs/adr/` holds the architecture
decision records that Section 3.2 requires for boundary changes.

Initial dependency candidates are Thousand Island for supervised sockets,
`rustler_precompiled` plus optional Rustler for the native boundary,
`crypto_box` and `zeroize` in Rust, Jason for bounded JSON decoding, Telemetry
for events, and StreamData for generative tests. WebSocket parsing may reuse
Cowlib if its byte-level API fits the transport adapter. Certificate and ACME
libraries are selected during the relevant milestone after an exact-parity
spike.

Dependencies are kept narrow. In particular, DERPEX does not embed Tokio or
the full official Rust client.

## 5. Test and oracle strategy

### 5.1 Upstream inventory

The baseline contains 69 named relevant Go tests:

| Area | Named tests |
| --- | ---: |
| DERP framing/client | 14 |
| DERP server | 25 |
| DERP HTTP | 11 |
| `cmd/derper` | 14 |
| DERP prober | 3 |
| XDP | 2 |

`interop/COVERAGE.md` inventories every test by package, name, upstream line,
and one of these dispositions:

- `black-box`: the scenario runs against DERPEX with an official Go client or
  raw Go protocol driver;
- `ported`: a language-neutral invariant is reproduced in ExUnit;
- `differential`: the same scenario runs against Go and DERPEX;
- `implementation-specific`: the assertion is Go-runtime-specific, with the
  protected observable behavior linked to another gate;
- `pending`: temporarily incomplete and therefore release-blocking.

No test may silently disappear, and a release may contain no `pending` rows.

### 5.2 Test layers

1. **Elixir unit tests** cover framing, limits, state transitions, queues,
   route selection, duplicate histories, rate limiters, HTTP responses, and
   configuration.
2. **Property tests** feed arbitrarily chunked streams, invalid lengths,
   unknown frame types, duplicate JSON fields, and concurrent lifecycle
   events. Parsers must never crash or allocate based on an unchecked length.
3. **Go black-box conformance tests** use unchanged official `derp.Client` and
   `derphttp.Client` code against a DERPEX listener. A raw Go driver supplies
   malformed and extension frames the normal client cannot emit.
4. **Oracle-health tests** execute the exact pinned Go packages represented by
   the compatibility inventory. They prove the reference remains reproducible;
   the reviewed mapping and DERPEX-facing gates prove implementation behavior.
5. **Differential tests** start the pinned Go server and DERPEX with equivalent
   identity/configuration, replay a scenario, normalize nondeterminism, and
   compare semantic traces.
6. **Rust interoperability tests** use the pinned `ts_derp` client for a
   separate handshake/send/receive smoke gate.
7. **Tailscaled-stack tests** run two pinned official `tsnet` nodes through
   LocalBackend, magicsock, WireGuard, and DERPEX, force the path away from
   direct UDP, and require Tailscale's DERP data counters to advance around a
   successful encrypted tunnel ping.
8. **System tests** cover TLS, WebSocket, STUN, signals, config reload,
   admission dependencies, and multiple OS processes.
9. **Gentility contract tests** run DERPEX with a version-matched fake and real
   mothership service through authorization, outage, revocation, reconciliation,
   quota, usage-spool, drain, and rollback scenarios.
10. **Artifact tests** inspect and boot the final OCI/OTP artifacts, asserting
   that no Go or Rust executable, compiler, source tree, or test helper entered
   the runtime filesystem.
11. **Benchmarks and soak tests** measure throughput, latency, mailbox growth,
   memory retention, and slow-client isolation.

### 5.3 Intended commands

The Mix project should expose stable aliases or tasks:

```text
mix test                 # unit and property tests
mix test.interop         # official Go and Rust clients against DERPEX
mix test.diff            # Go-vs-DERPEX behavioral oracle
mix test.system          # TLS, WebSocket, STUN, signals, external services
mix test.gentility       # authorization, revocation, quotas, accounting
mix test.all             # all release-blocking correctness gates
mix bench                # non-blocking benchmark suite
mix quality              # format, compile warnings, static analysis; no tests
mix artifact.check       # boot and inspect compiler-free release artifacts
mix release.check        # mix quality + test.all + artifact.check; the release gate
```

`mix quality` is the fast pre-commit gate: formatting, warnings-as-errors
compilation, Credo, `rustfmt`, and Clippy. It deliberately runs no tests, so
nothing that runs it may claim the suite passed. Tests under `test/system`
carry `@moduletag :system`, which `test/test_helper.exs` excludes by default,
so they run under `mix test.system` rather than a plain `mix test`. `mix
test.all` opts every tagged gate back in (`--include system --include
go_interop --include rust_interop`) and needs `DERPEX_TAILSCALE_DIR` and
`DERPEX_TAILSCALE_RS_DIR` pointing at the pinned checkouts. `mix release.check` runs `artifact.check` under `MIX_ENV=prod` in a
child Mix invocation, because the surrounding gate runs in `MIX_ENV=test`.

Fast pull-request CI runs unit tests and a compact Go interop slice. Full
differential, system, race-heavy, fuzz, and soak jobs run on main/nightly and
before release. No nightly-only failure may be waived for a release.

The release workflow cannot publish around those gates. `release.yml` calls
`ci.yml` as a reusable workflow in a job named `gate`, and every job that
builds, packages, or publishes an artifact lists `gate` in its `needs:`, so a
red quality, unit, Go interop, Rust interop, or runtime-boundary job blocks the
tag's release outright. `ci.yml` ignores `v*` tag pushes on its own trigger so
that gate is the tag's only run of the suite.

Go conformance jobs run in an isolated CI job and exchange only semantic test
results with the Elixir jobs. Go checkouts, caches, binaries, and toolchains are
excluded from every release build context and artifact.

Native CI has two deliberately separate paths. The ordinary CI job sets
`DERPEX_BUILD=1`, installs the pinned Rust toolchain, and runs formatting,
Clippy, Rust tests, warnings-as-errors compilation, and the Elixir tests against
the locally built NIF. After release artifacts exist, a consumer job
installs/builds the packaged application in a clean container without `cargo`
or `rustc`, proving that the default `rustler_precompiled` path is sufficient.

Native release preparation happens before the immutable tag. For a proposed
`X.Y.Z`, CI builds normalized archives for the four-target matrix and generates
the `rustler_precompiled` checksum manifest from those exact bytes. The manifest
lands in the release commit. CI then rebuilds from that commit and requires all
hashes to match before the commit is taggable. Pushing `vX.Y.Z` rejects a Mix
version mismatch, uploads the already-verified archives without modification,
verifies them again through `mix rustler_precompiled.download`, and publishes
multi-architecture Linux OCI/OTP artifacts. No workflow mutates source or
checksums after the tag.

The release consumer gate compiles from the tagged source using only the
precompiled NIF, then boots and inspects the final runtime image with no `go`,
`cargo`, `rustc`, Mix build tree, native source, or test driver present. Release
jobs pin Rust, Go, Erlang, Elixir, and third-party Actions by immutable version,
grant each job only its required GitHub permissions, and may retain a protected
environment approval for publication without making artifact construction
manual.

### 5.4 Differential trace model

The pinned Go server emits no trace, and the upstream checkout is never
modified, so the oracle can only observe what a client or a metrics scrape can
see. Trace events are therefore derived from two sources only:

1. frames observed by the driving clients, in per-connection order;
2. deltas of expvar/Prometheus counters and the `/debug/check` consistency
   endpoint, snapshotted between scenario steps.

Internal events such as enqueue, drop reason, and route change are compared
through their counters, not as first-class events. `derp/derpserver/fortest.go`
is inventoried in Milestone 0 for any additional exported hooks. Trace events
use stable logical records rather than logs, for example:

```text
connection_accepted
client_authenticated(key, app_name, mesh?, ideal?)   # from server-info / watcher frames
frame_received(connection, type, semantic_payload)   # client side
connection_closed(reason_class)
counter_delta(name, labels, delta)                   # metrics snapshot diff
consistency(check_output)                            # /debug/check
```

The Go oracle helper emits the same schema. Event comparison permits only
explicitly documented reorderings between independent connections.

`interop/go/differential_trace.go` is the single driver for both servers:
`oracle` mode starts the pinned Go server behind the same `/debug/varz` handler
`cmd/derper` publishes, and DERPEX mode drives the DERPEX relay and scrapes its
token-protected `/metrics`. The driver publishes only the per-server
`derpserver.Server.ExpVar` set; the `derp_packets_dropped` and
`derp_bytes_dropped` maps register themselves in the default expvar registry
during `derpserver` package initialization and need no help from the driver.
`test/interop/differential_test.exs` decodes both traces, compares them scenario
by scenario and step by step so a divergence names the step that produced it,
and then asserts whole-structure equality. Nothing in the trace is a literal
written by the driver.

The trace is a list of scenarios, each a list of steps. A step records the
frames its clients observed and the delta of every tracked counter since the
previous step. Three scenarios run in order:

- `relay_and_drops` — relay of empty, short, and `MaxPacketSize` payloads; a
  ping/pong exchange; a disco and a plain packet to never-connected keys; a
  flood that overruns both send queues of a recipient which has stopped
  reading, then that recipient catching up; and a disconnect observed by a peer.
- `duplicate_keys` — two connections sharing one public key plus a sender,
  covering newest-connection delivery, the older connection writing, and
  last-writer delivery.
- `watch_presence` — a trusted mesh watcher over the initial presence snapshot,
  a forwarded packet of each kind for a key this server does not hold, a later
  arrival, and a departure.

The tracked counter subset, named as Go's varz exposes it, is
`packets_sent`, `packets_received`, `packets_forwarded_in`, `packets_dropped`
for all seven reasons crossed with both packet kinds,
`peer_gone_disconnected_frames`, `peer_gone_not_here_frames`,
`total_dup_client_conns`, `current_dup_client_keys`, `current_dup_client_conns`,
`current_connections`, `unknown_frames`, `got_ping`, and `sent_pong`. A tracked
counter that a server does not publish fails the run rather than reading as
zero, so a missing counter cannot compare equal to a present one.

Only these normalizations are applied, identically to both traces:

1. Random node keys, addresses, and payload bytes become stable labels, a
   loopback boolean, and a size plus SHA-256 digest.
2. Metric names are canonicalized by trimming the `gauge_`/`counter_` type
   prefixes that Go's varz strips and DERPEX's `/metrics` keeps, and by sorting
   drop labels, which the two order differently.
3. Saturation is per counter, not per step. A step names the counters it
   compares by sign instead of by value, and every other counter in that step
   is compared exactly. Only two steps name any: the flood signs `packets_sent`
   and every `packets_dropped` cell, and the catch-up signs the
   `packets_dropped` cells. How many packets reach the socket before it blocks
   depends on kernel buffer sizes; the rest does not. In particular the flood
   still compares `packets_received` exactly (192), and the catch-up compares
   `packets_sent` exactly (65: a 32-deep ordinary queue, a 32-deep disco queue,
   and the packet in flight), which pins the send-queue depth.
4. The initial presence snapshot enumerates connected peers in unspecified
   order, so that one step's events are sorted. No other reordering is allowed.

Steps synchronize before snapshotting. Each waits for the server's
`current_connections` gauge to reach the expected value, and each round-trips a
ping on the connections whose accounting it depends on. A DERP server reads one
connection's frames in order and drains its pong queue last, so a received pong
proves both that the frames that client sent have been routed and that the
frames queued for it have been written and counted. The stalled recipient is the
one connection that cannot be pinged, which is why its send accounting is signed
rather than exact.

Each run also checks itself: across the flood and catch-up steps, the packets
the server accepted must equal the packets it wrote plus the packets it dropped
for a recorded reason, with nothing left over once the recipient has caught up
and disconnected. The check uses the raw deltas, not the signed ones, and fails
the run rather than the comparison, so a server that loses packets is caught
even when both servers lose them.

Five tracked cells stay zero-delta invariants because no unchanged official
client can drive them, and the upstream checkout may not be modified to add one:

- `unknown_frames` — the official client has no way to emit an unknown frame
  type. The invariant still catches a server that miscounts ordinary frames as
  unknown; driving a real unknown frame belongs to the raw-socket edge suite.
- `packets_dropped{*,dup_client}` — reached only when a key has two or more
  connections and none of them is currently the active one, a window the server
  opens and closes on its own schedule.
- `packets_dropped{*,gone_disconnected}` — requires a packet to be enqueued for
  a recipient that is already tearing down, which no client can time.
- `packets_dropped{*,queue_tail}` — Go tail-drops only after three failed
  head-drop attempts under racing writers, which a deterministic scenario
  cannot force.
- `packets_dropped{*,write_error}` — requires the recipient's socket write to
  fail, which means killing a connection mid-write and racing the two-second
  write deadline.

Every other cell is exercised: `unknown_dest` for both kinds by a disco and a
plain packet to never-connected keys, `unknown_dest_on_fwd` for both kinds by
the mesh watcher forwarding for a key this server does not hold, and
`queue_head` for both kinds by the flood, which overruns the ordinary queue
first and then the disco queue while the writer is stuck on the ordinary one.

`bytes_sent`, `bytes_received`, and `bytes_dropped` are excluded as a
byte-granularity restatement of the packet counters already compared.

The mesh coverage here is deliberately watch-scoped. It exercises the surface a
single server presents to a trusted peer — the presence snapshot, live presence
and departure updates, and an inbound forwarded packet — but not a real mesh of
two servers: no outbound forwarding, no `packets_forwarded_out`, no forwarder
registration or replacement, and no `close_peer`. Those paths belong to the mesh
interoperability suite, which runs DERPEX against a second live Go server.

## 6. Delivery milestones

Every milestone has a hard exit gate. From Milestone 2 onward each milestone
ends in a runnable vertical slice; Milestones 0 and 1 are foundations.

### Milestone 0: product contract, foundation, and frozen oracle

Deliverables:

- Create the supervised Mix project and a minimal OTP release configuration.
- Add formatting, warnings-as-errors, static analysis, unit test, and CI setup.
- Add the native crate skeleton, a `RustlerPrecompiled` loader with a
  NIF-not-loaded fallback, the optional `DERPEX_BUILD=1` source path, and the
  checksum-manifest integration point.
- Add source-build, no-Rust consumer, and tag-triggered precompiled-NIF workflow
  skeletons using the target matrix in Section 3.7.
- Commit `interop/upstream.lock` and checkout/bootstrap tooling.
- Generate the 69-test inventory and initial compatibility dispositions.
- Add a Go oracle/helper module without modifying the upstream checkout, and
  inventory the hooks exported by `derp/derpserver/fortest.go`.
- Implement `Derpex.Clock` with a real and a controllable test implementation.
- Freeze Gentility authorization-lease, revocation/reconciliation, quota-budget,
  usage-batch, drain, and regional-control contract v1 with a fake service.
- Commit the initial deployment profile: regions, reference instance types,
  static addressing, port exposure, DERP-map control, and failure domains.
- Set numeric prelaunch targets for connections, throughput, DERP traffic
  share, p95/p99 latency, queue age/drop rate, memory, overload behavior, and
  expected bandwidth cost on the reference instances.
- Record metadata classes, retention, debug authorization, crash-dump policy,
  billing aggregation, and abuse-response ownership.
- Isolate all Go oracle work in non-release CI jobs and exclude its entire
  checkout/toolchain from Docker and OTP release contexts.
- Record licensing/provenance for adapted BSD-3-Clause test scenarios.

Exit gate:

- A clean machine can resolve or validate both pinned upstream trees.
- CI proves the reference checkout is clean and at the expected SHA.
- `mix quality` exists and passes for the empty skeleton.
- CI proves the explicit source-build path and validates the release-workflow
  definition; the precompiled consumer gate becomes active in Milestone 1 once
  real crypto artifacts exist.
- Contract fixtures pass from both the DERPEX and Gentility sides, including
  canonical encoding and incompatible-version behavior.
- Numeric capacity/SLO targets and the privacy/abuse policy have named owners;
  they are no longer deferred implementation inputs.
- A skeleton runtime artifact boots with no Go or Rust toolchain present.
- Every upstream test appears once in the coverage inventory.

### Milestone 1: wire codec, JSON compatibility, and crypto

Deliverables:

- Encode/decode the five-byte header and all frame type constants.
- Implement incremental parsing across arbitrary TCP chunk boundaries.
- Encode all server-emitted frame bodies and parse all client-emitted bodies.
- Enforce packet, info, ping, app-name, and frame-specific length rules before
  allocation.
- Implement Go-compatible client-info JSON behavior: accepted field casing,
  unknown fields, duplicate fields, zero values, mesh-key validation, and
  printable-ASCII app names up to 32 bytes.
- Implement the Rust identity resource and NaCl box operations.
- Add deterministic Go/Rust/Elixir interoperability vectors.
- Produce checksum-verified precompiled crypto artifacts for every supported
  target and exercise their download/load path in CI.
- Implement and document the reader/Outbox/Writer decomposition with the
  fixed-capacity ring from Section 3.5. Exercise a saturating sender against a
  stalled writer, including drop-head replacement, wake-up coalescing,
  disconnect races, and counters.

Exit gate:

- All portable tests from Go `derp.go`, `derp_client.go`, and key handling are
  mapped and passing.
- Packet-bearing storage remains structurally fixed at configured capacity and
  the Outbox mailbox contains at most its coalesced control wake-up under a
  saturating sender while the Writer is stalled, with no sender blocked.
- Go can decrypt server info sealed by DERPEX and DERPEX can decrypt client
  info sealed by Go.
- All target archives are created by GitHub Actions, and a clean consumer can
  compile and load the NIF without `cargo` or `rustc` installed.
- Chunking and malformed-frame property tests pass without crashes or
  unchecked large allocations.
- No packet-path function calls the NIF.

### Milestone 2: native TLS, identity, and authenticated connection

Deliverables:

- Implement the Thousand Island connection handler and transport abstraction.
- Parse bounded HTTP/1 request lines and headers incrementally.
- Implement `/derp` native upgrade with exact 101 status and headers.
- Implement `Derp-Fast-Start: 1` takeover with no HTTP response.
- Preserve bytes read ahead of the HTTP-to-DERP transition.
- Persist the node private key atomically with restrictive permissions and
  preserve identity across restart.
- Serve TLS 1.3 with manual certificates, `http/1.1` ALPN, DERP metacert
  fast-start, and an atomic certificate hot-reload path.
- Implement server-key/client-info/server-info handshake ordering and the
  ten-second unauthenticated deadline.
- Add `/derp/probe`, `/derp/latency-check`, and `/generate_204` early.
- Prove a thin WebSocket byte-stream adapter before committing the final
  implementation choice.
- Time-box a comparison of a fully custom `Derpex.HTTP1` against Bandit/Plug
  for the non-DERP surface with a raw path for `/derp`; the two cannot share a
  listener without a custom front, which is the likely deciding factor. Record
  the outcome as an ADR.

Exit gate:

- An unchanged official Go `derphttp.Client` completes a cleartext HTTP
  upgrade plus native TLS and authenticated handshakes.
- A raw client verifies the exact standard and fast-start byte sequences.
- Slowloris request/header and handshake tests terminate within configured
  limits.
- Restart preserves identity, and certificate reload changes new handshakes
  without interrupting established connections.
- The transport spike proves TCP, TLS, and WebSocket writers can be isolated
  from their readers without violating socket ownership.

### Milestone 3: single-node relay correctness and edge behavior

Deliverables:

- Implement authenticated registration and ETS local-route lookup.
- Implement outbox admission, writer lifecycle, and frame ordering.
- Relay `SendPacket` to `RecvPacket` with the exact 32-byte source prefix.
- Match last-writer-is-active duplicate behavior, promotion, and disconnect
  collapse.
- Track reverse paths so recipients receive disconnect notifications only
  after a source has actually sent to them.
- Detect disco wrappers exactly as Go does.
- Emit `PeerGone(NotHere)` only for eligible disco packets, with burst three
  and one-per-second refill.
- Emit `PeerGone(Disconnected)` only when the source is gone from the whole
  currently known region.
- Implement ping-to-pong, keepalive jitter, preferred notes, and unknown-frame
  discard.
- Enforce two-second regular and thirty-second privileged write timeouts.
- Drain disconnected rings into the correct drop counters and add consistency
  checks for route, duplicate, and reverse-watch state.
- Ensure server-info precedes packets queued during registration.
- Add core counters and connection gauges needed for assertions.

Exit gate:

- Official Go clients pass multi-client send/receive and ping scenarios.
- Zero-length and 64 KiB payload boundaries match Go; oversize frames close in
  the same phase.
- Adapted duplicate-client, `PeerGone`, and `TestSendFreeze` scenarios pass.
- Differential drop counters and disconnect frames match the Go oracle.
- Independent client flows continue when one recipient stops reading.
- There is no global-router hop on a successful local packet lookup.

### Milestone 4: Gentility authorization, quotas, and accounting

Deliverables:

- Implement `Derpex.Admission.Gentility` against contract v1 with authenticated
  leases and bounded memory/durable caches.
- Attribute every accepted connection to node, organization, owner kind, and
  deployment without exposing those identifiers as unbounded metric labels.
- Permit unexpired cached reconnects during outage; deny unknown/expired nodes
  and close existing connections at expiry.
- Consume the revocation stream, close every local duplicate promptly, and
  reconcile policy revisions after missed events or reconnect.
- Enforce locally allocated per-node and per-organization connection and byte
  budgets, including live revision and exhaustion behavior.
- Aggregate usage in fixed windows and export idempotent batches through a
  bounded durable spool.
- Implement per-IP unauthenticated handshake/connection caps and bounded
  admission-controller work.

Exit gate:

- Joint Gentility/DERPEX contract tests pass for authorize, reconnect, expiry,
  revocation, reconciliation, key rotation, quota revision, and usage replay.
- A mothership outage permits only the explicitly leased window and produces a
  measured upper bound on missed-revocation time.
- Organization limits remain locally enforceable during outage with the
  documented bounded global overshoot from regional allocations.
- Admission cache, request concurrency, and usage spool remain bounded under
  hostile node keys, churn, and prolonged dependency outage.

### Milestone 5: STUN, probes, observability, and graceful drain

Deliverables:

- Implement the UDP STUN behavior used by DERP maps and netcheck.
- Finish `/derp/probe`, `/derp/latency-check`, `/generate_204`, health, metrics,
  and the minimum authenticated operational endpoints.
- Implement receive-byte and accept-connection limiting, including live
  Gentility budget changes and TCP backpressure.
- Implement graceful drain: stop new home connections, optional bounded-jitter
  restart notices, a hard deadline, idempotent shutdown, and rollback.
- Export dashboards and alerts for availability, handshake failures, latency,
  saturation, queue age/drops, revocation lag, quota exhaustion, usage backlog,
  memory, scheduler pressure, and STUN reachability.
- Document network/provider volumetric controls for TCP/TLS and UDP 3478; STUN
  application limits must not break normal netcheck behavior.

Exit gate:

- Official netcheck/prober code can measure a local DERPEX node through native
  TLS and STUN.
- Drain tests prove admission stops, restart frames occur only in the Gentility
  profile, clients receive bounded jitter, and the deadline leaves no resources.
- Alert and external-probe failure injections reach the documented owner.
- Volumetric simulations degrade according to the declared overload policy
  without unbounded application state.

### Milestone 6: capacity proof and regional preproduction rollout

Deliverables:

- Deploy dedicated DERPEX OTP releases into at least two independent
  preproduction regions with static IPv4/IPv6, direct TCP 443, and UDP 3478.
- Publish and canary the DERP-map entries, exercise emergency withdrawal, and
  execute upgrade, drain, rollback, and region-loss runbooks.
- Run synthetic and controlled preproduction overlay traffic from multiple
  networks; no Go DERP is part of this topology.
- Benchmark and soak the reference instance types against every numeric target
  fixed in Milestone 0, including Gentility's expected elevated DERP share.
- Evaluate Peer Relays for the high-throughput restricted-network paths named
  in Section 3.6 and record the product/topology decision.

Exit gate:

- Both regions meet connection, throughput, p95/p99 latency, queue-age/drop,
  memory, overload, and bandwidth-cost targets on the declared hardware.
- Region withdrawal and rollback restore healthy routing within the declared
  SLO with authorization, revocation, and accounting continuity.
- The final OCI image boots with its precompiled NIF and contains no Go or Rust
  toolchain, build cache, native source, or conformance helper.
- Privacy, abuse, dashboards, alerts, runbooks, and on-call review are signed
  off by their Gentility owners.

### Milestone 7: WebSocket, HTTP, and baseline operational parity

Deliverables:

- Finish WebSocket upgrade validation, `derp` subprotocol negotiation, binary
  stream adaptation, close behavior, and disabled compression.
- Match upgrade-required, probe method, CORS, no-content challenge, cache, and
  related HTTP headers/statuses.
- Preserve `Ideal-Node` connection metadata.
- Implement receive-byte token buckets based on DERP frame payload length.
- Clamp configured burst to the minimum valid send-packet frame and pace reads
  to create TCP backpressure.
- Apply live rate updates to all ordinary duplicate connections and exempt
  mesh peers.
- Implement accept-connection rate/burst limiting.
- Implement disallowed app names, admission controller request/response
  limits, and fail-open/fail-closed policy.
- Implement a minimal LocalAPI client over the tailscaled Unix socket
  (`/localapi/v0/whois`) for `--verify-clients`; this is a small HTTP client,
  not a configuration check.
- Emit the tested metrics, drop labels, queue-duration average, sender
  cardinality estimate, RTT buckets where supported, and debug varz.
- Implement tested consistency and traffic debug endpoints, including Linux
  socket-stat parsing where applicable.

Exit gate:

- Rate configuration load/reload, pacing, cancellation, clamping, and mesh
  exemption scenarios pass.
- Admission tests cover allow, deny, unavailable dependency, malformed
  response, response-size cap, and mesh bypass.
- Metric names, types at the HTTP boundary, and label values satisfy the
  compatibility inventory.
- Observability work adds no unbounded per-sender state.
- A WebSocket client performs handshake, relay, ping, and disconnect tests.
- HTTP golden tests match the Go oracle byte-for-byte where ordering is
  normative and header-semantically elsewhere.

### Milestone 8: bootstrap DNS and ancillary HTTP parity

Deliverables:

- Implement bootstrap DNS publication, unpublished rollout, lookup accounting,
  and response behavior.
- Implement homepage modes, robots response, redirects, and disabled-DERP
  responses.
- Match HTTP/HTTPS listener selection and port-80 behavior for manual
  certificate mode.

Exit gate:

- Pinned `cmd/derper` bootstrap DNS, no-content, and template scenarios are
  mapped and passing.
- Ancillary endpoints retain no additional peer metadata beyond the policy
  fixed in Milestone 0.

### Milestone 9: ACME and IP certificates

This is the stable surface most likely to slip and least likely to block a
deployment behind a proxy or with manual certificates, so it is isolated and
scheduled last among the stable surfaces before the CLI milestone.

Deliverables:

- Implement the ACME certificate provider required by the pinned CLI,
  including hostname policy, GCP EAB, port-80 challenges, and the default
  `letsencrypt` cert mode.
- Implement raw-IP pinning, short-lived IP certificates, and provider
  rotation.
- Select the ACME dependency after an exact-parity spike.

Exit gate:

- Pinned `cmd/derper` certificate and IP certificate scenarios are mapped and
  passing.
- Certificate renewal/provider rollover works under `Derpex.Clock` and a fake
  ACME service.

### Milestone 10: complete CLI and optional ACE parity

Deliverables:

- Implement the compatible executable flags and validation rules.
- Load the Go-compatible configuration representation.
- Implement development mode, DERP-only, STUN-only, and decommissioning modes.
- Implement SIGHUP rate-config reload and graceful SIGINT/SIGTERM shutdown.
- Match TCP keepalive, write-timeout, listener, and shutdown settings.
- Match `--tcp-user-timeout` (15s default) on Linux via
  `:inet.setopts(sock, [{:raw, 6, 18, <<ms::32-native>>}])` (`TCP_USER_TIMEOUT`);
  a no-op with a logged notice elsewhere.
- Accept and reject the setec `--secrets-*` flags per Section 2.3.
- Implement tested dependency-free equivalents of the debug and health
  surfaces.
- Implement experimental ACE behind its disabled-by-default flag, or record a
  user-approved scope amendment if upstream removes it before this milestone.
- Produce an OTP release and container-ready runtime configuration whose build
  and runtime stages contain no Rust toolchain.

Exit gate:

- CLI golden tests and invalid-configuration tests match the Go executable.
- Restart preserves server identity and remains interoperable.
- Signal tests leave no listener, mesh connection, timer, or temporary key
  file behind.
- The complete stable tested `cmd/derper` surface has no pending coverage row.

### Milestone 11: optional regional mesh parity

Deliverables:

- Parse and compare the 32-byte mesh key in constant time.
- Exempt trusted mesh clients from ordinary admission and receive rate limits.
- Implement `WatchConns`, initial presence flood, live presence batching, and
  disconnect updates.
- Emit modern `PeerPresent` with key, 16-byte IP, port, flags, app-name length,
  and app name.
- Implement outbound mesh client connections and reconnect loops.
- Register/remove remote forwarders, including multiple forwarders.
- Forward local packets one hop and never re-forward `ForwardPacket`.
- Implement privileged `ClosePeer` for every local duplicate connection.

Exit gate:

- Official Go watcher tests pass for flags, IP/port, app names, initial flood,
  and live changes.
- Two-node and three-node regional meshes deliver packets and converge after
  connection failure.
- Loop-prevention tests prove forwarded packets cannot make a second mesh hop.
- Multi-forwarder concurrent add/remove tests lose no accepted forwarding
  request.

### Milestone 12: integrated audit, performance, and release candidate

Deliverables:

- Run every mapped upstream test disposition and close all pending rows.
- Run full Go-vs-DERPEX differential scenarios repeatedly with randomized
  scheduling and chunking.
- Run official Go, official Rust, and a real `tailscaled` integration smoke
  test.
- Run the real Gentility control plane through authorization, revocation,
  reconciliation, quota, accounting, region withdrawal, drain, and rollback.
- Fuzz HTTP, WebSocket, DERP framing, encrypted JSON, mesh changes, and
  disconnect races.
- Benchmark packet sizes 0, 64, typical WireGuard MTU, and 64 KiB across 1:1,
  fan-in, fan-out, and mesh paths.
- Soak idle connections, churn, duplicates, slow readers, and mesh reconnects.
- Profile reductions, scheduler utilization, memory, binary retention, ETS
  contention, mailbox lengths, and socket buffering.
- Complete security review of the NIF, length validation, secret persistence,
  admission boundaries, and TLS configuration.
- Cut a release candidate through the tag-triggered precompiled-NIF pipeline
  and verify every advertised artifact and checksum from a clean environment.

Exit gate:

- `mix release.check` passes repeatedly on supported platforms.
- The release candidate installs and starts on every supported target without
  `go`, `cargo`, or `rustc`, using only the published checksum-verified NIF
  archive.
- Every one of the 69 baseline tests is accounted for with no pending row.
- No known observable difference exists without a documented, user-approved
  compatibility exception.
- Long-running tests show bounded mailboxes, queues, timers, and binary memory.
- Both independent regions meet the Gentility contract and Milestone 0 SLOs
  under normal operation, control-plane outage, revocation, overload, and
  regional failure.
- Performance results and capacity limits are published; native data-path work
  is considered only if a measured bottleneck justifies it.

## 7. Performance plan

Correctness gates are absolute. Milestone 0 fixes numeric launch targets and
reference instance types with Gentility; the corresponding measurements are
release blockers. Go comparisons remain diagnostic rather than replacing those
product SLOs.

The baseline report records Go and DERPEX on the same host for:

- handshake CPU and latency;
- idle memory per native, TLS, and WebSocket connection;
- packets and bytes per second at representative sizes;
- p50/p95/p99 relay latency;
- one-destination fan-in contention;
- unrelated-flow behavior under a blocked destination;
- two-node mesh overhead;
- connection churn and duplicate-key churn.

Optimization order is:

1. remove accidental binary copies and flattening;
2. batch writer iodata without changing frame order;
3. tune socket watermarks, send timeout, and listener concurrency;
4. reduce synchronous router work and ETS contention;
5. shard only the measured contended state;
6. consider native code only after the above are exhausted.

## 8. Security and robustness rules

- Never derive atoms from network input.
- Check frame and HTTP lengths before allocating or decoding.
- Cap unauthenticated HTTP headers, handshake bytes, JSON depth/size where the
  decoder permits, admission responses, and debug request bodies.
- Use constant-time equality for mesh credentials.
- Keep server private-key material out of logs and exception inspection.
- Never log encrypted payloads or persist per-peer traffic relationships.
- Retain source IP, node, organization, timing, size, and outcome metadata only
  at the aggregation and duration approved in the Milestone 0 privacy policy.
- Authorize every debug/traffic endpoint independently of public health and
  probe endpoints.
- Disable production ERTS crash dumps or write them to access-controlled,
  encrypted, retention-limited storage because they may contain keys or packet
  binaries.
- Persist keys atomically with mode `0600` or a stricter platform equivalent.
- Treat every NIF error as data; malformed input must not panic Rust or crash
  the VM.
- Accept native code only from the version-matched GitHub Release through the
  committed `rustler_precompiled` SHA-256 manifest.
- Supervise all long-lived work and make cleanup idempotent.
- Do not rely on process mailbox growth as backpressure.
- Test abrupt TCP close, half-close, TLS alert, writer timeout, process kill,
  supervisor restart, and dependency outage.
- Keep privileged mesh actions unavailable until authentication is complete.

## 9. Risk register

| Risk | Mitigation | Burn-down milestone |
| --- | --- | --- |
| Fast-start conflicts with conventional HTTP server ownership | Raw-handler spike, read-ahead tests, exact wire capture | 2 |
| WebSocket byte-stream semantics differ from native DERP | Shared transport behavior and official binary-frame tests | 2 and 6 |
| NaCl incompatibility or unsafe NIF behavior | Minimal Rust boundary, cross-language vectors, dirty CPU for large decrypts | 1 |
| Missing, corrupt, or mismatched precompiled NIF | Pre-tag manifest, release-blocking target matrix, no-toolchain consumer smoke tests | 0, 1 and 12 |
| Slow recipients grow BEAM mailboxes | Structurally bounded ring from M1, saturation tests | 1 and 3 |
| Duplicate/mesh races create stale routes | Serialized topology updates, ETS invariants, differential randomized tests | 3 and 11 |
| Gentility outage admits revoked or unknown nodes | Expiring authenticated leases, push revocation, reconciliation, fail-bounded tests | 0 and 4 |
| Distributed org limits overshoot during partition | Versioned regional budgets with a declared aggregate overshoot bound | 0, 4 and 6 |
| Usage outage loses billing records or grows disk | Idempotent fixed windows and bounded durable spool with alerting | 4 and 5 |
| Relay traffic exceeds normal DERP assumptions | Numeric elevated-share SLOs, overload policy, Peer Relay ADR | 0 and 6 |
| Literal Go tests cannot target another language | Complete test inventory plus black-box and differential mappings | 0 onward |
| Rust client lags current Go frame extensions | Go remains normative; Rust is smoke-only | permanent |
| TLS metacert or provider chain differs by runtime | Certificate golden tests and Go fast-start observation | 2 and 9 |
| Operational `cmd/derper` scope overwhelms core delivery | Vertical milestones with protocol parity usable before final binary parity | all |
| Wall-clock timers make differential tests flaky or slow | `Derpex.Clock` from M0; no direct clock reads | 0 |
| Differential oracle promises events Go cannot expose | Trace model limited to client-observed frames and counter deltas | 0 |
| Custom HTTP/1 server grows to cover the whole derper surface | M2 time-boxed spike against Bandit/Plug, ADR | 2 |

## 10. Definition of done

DERPEX is complete for the pinned baseline when:

- all release-blocking Mix, Go interop, differential, Rust interop, and system
  gates pass;
- all 69 relevant baseline Go tests have a reviewed disposition and none are
  pending;
- unchanged official Go clients can use native HTTP, TLS fast-start, and mesh
  paths;
- two official `tsnet` nodes can exchange encrypted tunnel traffic through
  DERPEX with Tailscale's send and receive DERP data counters advancing;
- the official Rust client completes its supported DERP flow;
- tested `cmd/derper` HTTP, TLS, STUN, certificate, admission, configuration,
  metrics, and lifecycle behavior is present;
- Gentility lease authorization, attribution, active revocation,
  reconciliation, regional quotas, and usage export pass joint contract and
  outage tests;
- at least two independent dedicated regions meet the declared SLOs and have
  exercised DERP-map canary, drain, withdrawal, upgrade, and rollback runbooks;
- malformed input and dependency failures do not crash the VM or leak
  resources;
- supported deployments install and start from checksum-verified precompiled
  NIFs without Go or Rust toolchains;
- runtime artifacts, telemetry, debug access, crash-dump handling, and metadata
  retention satisfy the approved privacy and abuse policies;
- queues, mailboxes, ETS state, timers, and retained binaries stay bounded in
  soak tests;
- performance characteristics and supported capacity are documented; and
- any remaining observable deviation has explicit user approval recorded in
  the compatibility matrix.

## 11. Deferred inputs that do not block implementation

These decisions are intentionally deferred until evidence is available:

- supported production OS/architecture matrix beyond the initial targets in
  Section 3.7;
- capacity targets beyond the initial reference instances and launch SLOs;
- additional deployment packaging beyond the multi-architecture OCI image and
  OTP release;
- ACME provider dependency selection (Milestone 9);
- whether metrics must be byte-for-byte Prometheus compatible or only preserve
  all documented names, values, and labels.

The defaults are macOS/Linux development, Linux production, OTP release plus a
container artifact, semantically identical Prometheus exposition, and no
native packet path.
