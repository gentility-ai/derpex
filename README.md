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

`DERPEX_DISALLOWED_APP_NAMES` is an optional comma-separated list of exact
client-advertised app names to reject before registration. Trusted mesh peers
are exempt, matching the baseline server. Embedders can also supply a
`Derpex.Admission` policy in listener handler options for product authorization.

Set `DERPEX_RATE_CONFIG` to an upstream-compatible JSON file containing
`PerClientRateLimitBytesPerSec` and `PerClientRateBurstBytes`. Enabled buckets
are clamped to hold at least one maximum DERP packet, and live updates through
`Derpex.RateController.load_and_apply/1` reach every ordinary duplicate
connection while trusted mesh peers remain exempt.
