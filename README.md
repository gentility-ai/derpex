# DERPEX

DERPEX is an Elixir implementation of Tailscale's DERP server and the relay
service for Gentility's overlay. The compatibility and product delivery contract
is maintained in [`PLAN.md`](PLAN.md).

The packet data path stays on the BEAM. A small Rust NIF is limited to the
NaCl-compatible cryptography used by the DERP handshake and is distributed with
`rustler_precompiled` so production deployments contain no compiler toolchain.

## Development

The native crate is built from source for prerelease versions:

```sh
mix deps.get
mix quality
```

Go and the pinned upstream repositories are conformance-test inputs only. They
must never be copied into an OTP release or runtime image.

## Runtime listener

The release starts with no listener unless explicitly configured. A direct TLS
1.3 listener requires the identity and certificate paths:

```sh
DERPEX_LISTEN_PORT=443 \
DERPEX_IDENTITY_PATH=/var/lib/derpex/derpex.key \
DERPEX_TLS_CERTFILE=/run/secrets/derpex.crt \
DERPEX_TLS_KEYFILE=/run/secrets/derpex.key \
bin/derpex start
```

The server identity is created atomically with mode `0600` and is stable across
restarts. The UDP STUN service listens on port `3478` by default whenever the
DERP listener is enabled. Set `DERPEX_STUN_PORT` to change it or
`DERPEX_STUN=0` to disable it. Clear HTTP is available only through the
explicit `DERPEX_CLEAR_HTTP=1` development setting.

Regional connection watching is disabled unless `DERPEX_MESH_KEY` contains a
64-digit hexadecimal key. Trusted clients advertise the same key in their
encrypted `ClientInfo`; comparisons are constant-time and untrusted clients
cannot subscribe to presence updates.

Set `DERPEX_MESH_WITH` to a comma-separated list of peers to enable outbound
regional meshing. Each entry may be a complete `https://host/derp` URL, a host
name (which expands to that URL), or `host/dial-host` to preserve TLS identity
while dialing a private address. A configured mesh requires
`DERPEX_MESH_KEY`. Connections watch and withdraw remote routes automatically,
use bounded forwarding queues, and reconnect every five seconds after failure.

`DERPEX_SEND_QUEUE_DEPTH` sets the independent ordinary and discovery packet
ring capacities for each client (default `32`). The upstream
`TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH` name is also accepted for parity.
Control/lifecycle traffic retains separate fixed rings.

`DERPEX_DISALLOWED_APP_NAMES` is an optional comma-separated list of exact
client-advertised app names to reject before registration. Trusted mesh peers
are exempt, matching the baseline server. Embedders can also supply a
`Derpex.Admission` policy in listener handler options for product authorization.

Set `DERPEX_RATE_CONFIG` to an upstream-compatible JSON file containing
`PerClientRateLimitBytesPerSec` and `PerClientRateBurstBytes`. Enabled buckets
are clamped to hold at least one maximum DERP packet, and live updates through
`Derpex.RateController.load_and_apply/1` reach every ordinary duplicate
connection while trusted mesh peers remain exempt.

Set both `DERPEX_ACCEPT_CONNECTION_LIMIT` (connections per second) and
`DERPEX_ACCEPT_CONNECTION_BURST` to bound unauthenticated connection creation.
The shared bucket is checked before crypto, ring, or session allocation.

## Gentility profile

The baseline profile remains the default. A production Gentility deployment
includes one adapter module implementing
`Derpex.Admission.Gentility.ControlPlane` in the OTP release, then sets:

```sh
DERPEX_GENTILITY_ADAPTER=Gentility.DERPControlPlane
DERPEX_GENTILITY_VERIFY_KEYS='2026-08:<base64-ed25519-public-key>'
DERPEX_GENTILITY_CACHE_PATH=/var/lib/derpex/admission.cache
DERPEX_GENTILITY_USAGE_SPOOL_PATH=/var/lib/derpex/usage.spool
DERPEX_GENTILITY_INSTANCE_ID=derpex-sin-1
DERPEX_GENTILITY_REGION_ID=17
```

The adapter owns its transport and transport authentication configuration; it
returns only contract-v1 signed lease/revocation records and accepts canonical
content-addressed usage batches. DERPEX starts the controller before listeners,
resolves each listener to a lock-free policy handle, and uses `:rest_for_one`
restart ordering so controller failure also replaces every stale listener
handle. The event consumer reconciles before consuming revocations and repeats
reconciliation after every stream failure. Set `DERPEX_GENTILITY_EVENTS=0`
only for isolated contract tests; active revocation is required in production.

Cached leases and usage batches are atomically persisted with mode `0600`.
Unknown and expired nodes fail closed during outage. A full usage spool stops
packet admission instead of dropping accounting data or growing memory.
