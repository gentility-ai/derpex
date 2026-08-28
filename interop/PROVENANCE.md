# Interoperability provenance

DERPEX treats the pinned Tailscale Go implementation as the normative DERP
behavioral specification. The Rust implementation is an additional source of
implementation insight and smoke interoperability; it cannot override Go
behavior.

| Source | Pinned revision | License | Use |
| --- | --- | --- | --- |
| `tailscale/tailscale` | `1e69418c298b680562a2fecd7020f7f58d17d166` | BSD-3-Clause, copyright 2020 Tailscale Inc & contributors | Protocol behavior, differential oracle, adapted tests |
| `tailscale/tailscale-rs` | `1a969ad5dd753aa3b2bbb91499ed64cc6baef621` | BSD-3-Clause, copyright 2026 Tailscale Inc & contributors | Secondary implementation reference and smoke client |

Exact repository URLs and toolchains are recorded in `interop/upstream.lock`.
Adapted source or tests retain the upstream copyright and SPDX identifier in
their file header. The upstream checkouts and Go/Rust reference toolchains are
development and isolated-CI inputs; they are not copied into the DERPEX runtime
image.

This notice does not select a license for original DERPEX code. A project-wide
license remains a product-owner decision.
