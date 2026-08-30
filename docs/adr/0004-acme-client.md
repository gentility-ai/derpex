# ADR 0004: a hand-written ACME client, no new dependencies

Status: accepted for Milestone 9 (plan task F3).

## Context

PLAN.md section 2.3 records ACME as pending, not excepted. `DERPEX_CERT_MODE`
`letsencrypt` and `gcp` are refused at boot, and the `TestIPCertManager` and
`TestIPCertManagerNextProvider` inventory rows stay release-blocking until an
RFC 8555 client exists.

The pinned Go oracle sets the parity bar. `cmd/derper` uses two ACME paths:

- `ipcert.go` orders **IP identifiers** (`acme.IPIDs(ipStr)`) under the
  **`shortlived` profile** (`acme.WithOrderProfile`), fulfils **HTTP-01** on the
  plaintext port, and finalizes a CSR carrying exactly one IP SAN.
- `cert.go` uses `autocert` for the DNS hostname path, with an
  **external account binding** (kid plus HMAC key) when `--certmode=gcp`.

The vendored client at `../tailscale/tempfork/acme` is the normative source for
the wire format: `jws.go` for ES256 JWS, JWK encoding and the HS256 EAB inner
JWS, `rfc8555.go` for registration, `newOrder`, finalize and download.

## Hex library survey

Searched hex.pm (August 2026) and read the two maintained candidates:

| Package | Last release | EAB | `ip` identifier | `profile` field | Runtime deps |
| --- | --- | --- | --- | --- | --- |
| `acme_client` 2.0.5 | 2026-05 | yes | no — `%{type: "dns"}` only | no | `jose`, `idna` |
| `ex_acme` 0.8.0 | 2026-07 | not documented | not documented | no | `x509`, HTTP client |
| `acmex` 0.2.0 | 2020-08 | no | no | no | `jose`, `httpoison` |
| `acme` 0.5.1 | 2017-12 | no | no | no | `httpoison` |
| `p1_acme` 1.0.31 | 2026-03 | no | no | no | `jose`, `yconf`, `idna` |

No published library implements either feature the IP-certificate path depends
on. The RFC 8555 profiles extension is a 2025 draft that none of them carry, and
IP identifiers appear nowhere. Adopting one would mean forking it and then still
writing both features by hand.

The cost of adopting is not only the fork. DERPEX holds its release to a
twelve-application runtime closure, gated by `scripts/dependency_closure.exs`
because the pinned `TestDeps` protects the same invariant for `cmd/derper`.
`jose` plus `idna`, or a Finch/Mint stack, would be a deliberate and permanent
widening of that closure to obtain a client that does not do the job.

## Decision

Write the client, using only OTP. No dependency changes; the closure allowlist
is untouched.

`lib/derpex/acme/`:

- `jws.ex` — ES256 over P-256, RFC 7638 JWK thumbprint, HS256 EAB inner JWS.
- `directory.ex` — directory fetch, `meta.profiles` support check.
- `account.ex` — account key load/create (0600), `newAccount` with optional EAB.
- `order.ex` — `newOrder` with one identifier and an optional profile, poll,
  finalize, download.
- `challenge.ex` — HTTP-01 token, key authorization, challenge path.
- `csr.ex` — PKCS#10 with exactly one DNS or one IP SAN.
- `client.ex` — nonce handling, POST-as-GET, retry and backoff, orchestration.

Existing DERPEX components are reused rather than duplicated:
`Derpex.HTTPClient` for transport, `Derpex.JSON` for encoding,
`Derpex.AtomicFile` for the 0600 account and certificate keys, `Derpex.Clock`
for every deadline, and `Derpex.Certificates.IPManager`'s existing renewal tick
and one-minute-to-thirty backoff from plan task F2.

The client is injected into `IPManager` as its `:issuer`, the same seam the
self-signed issuer already uses, so nothing on the handshake path changes.
HTTP-01 responses are served through the challenge route `IPManager` already
exposes.

### Feasibility spike

Both genuine unknowns were resolved before accepting this ADR:

- **ES256 JWS.** `:public_key.sign/3` returns a DER `ECDSA-Sig-Value`; JWS wants
  raw `r || s`. Decoding with `:public_key.der_decode(:"ECDSA-Sig-Value", …)`,
  re-encoding as two fixed 32-byte integers, and verifying the rebuilt DER
  round-trips through `:public_key.verify/4` works.
- **PKCS#10.** OTP's `PKCS-10` ASN.1 module encodes a `CertificationRequest`
  directly. The `extensionRequest` attribute values are `SET OF ANY`, so each
  must be wrapped as `{:asn1_OPENTYPE, der}` — the one non-obvious detail. The
  resulting CSR passes `openssl req -verify` and reports exactly
  `X509v3 Subject Alternative Name: IP Address:203.0.113.7`.

## Transport rules

Three rules are enforced rather than assumed, because a certificate authority
supplies the URLs its own responses are fetched from:

- Every ACME URL must be HTTPS. The single exception is a loopback host
  (`127.0.0.0/8`, `::1`, `localhost`), which is how the fake authority in the
  test suite is reached and is not reachable off the machine. This is checked
  at boot for `DERPEX_ACME_DIRECTORY_URL` and again on every request.
- Every URL after the directory must share the directory's origin — scheme,
  host, and effective port. RFC 8555 does not require the `certificate`
  download to live elsewhere and no supported authority puts it elsewhere, so a
  cross-origin URL is refused rather than followed. If an authority ever needs
  it, the refusal names the URL and the pinned origin.
- `Derpex.HTTPClient` forces `verify_peer` and the hostname check after any
  caller-supplied TLS options, so a caller can pin its own trust anchors but
  cannot turn verification off.

Key material held by a long-lived process is wrapped in `Derpex.Secret`: the
manager keeps no issuer private key at all and holds only a wrapped DER copy
for `:ssl`, and the client holds its account key and external-account HMAC key
wrapped. `format_status/1` covers `:sys.get_state/1` and the terminate report;
the wrapper covers what neither reaches, including the arguments an exception
renders into a crash report.

## Consequences

DERPEX owns an ACME implementation and its maintenance. That is accepted: the
surface is small, it is pinned to the behaviour of a vendored Go client that is
itself checked into the oracle, and the parity requirements are already
expressed as upstream tests.

Testing follows the oracle. `fakeIPACME` from
`../tailscale/cmd/derper/ipcert_test.go` is ported to `test/support/fake_acme.ex`
so the same order flow — JWS payload inspection, HTTP-01 fetched back with a
key-authorization check, CSR parsed for exactly one SAN, order counting — gates
the Elixir client.

Nothing in this ADR changes the handshake path, the certificate cache format, or
the boot-time refusal of a mode until the client behind it passes those tests.
