# Upstream compatibility inventory

Generated from Tailscale commit `1e69418c298b680562a2fecd7020f7f58d17d166` by:

```sh
elixir scripts/upstream_inventory.exs ../tailscale --output interop/COVERAGE.md
```

Do not remove a row manually. Change the generator's explicit scope or
disposition map and review that change together with `interop/upstream.lock`.
The generator refuses to write this file unless every non-pending row cites
a repository path that exists, and every `ported`, `black-box`, and
`differential` row cites a DERPEX test file.

| Disposition | Meaning |
| --- | --- |
| `ported` | DERPEX has its own test for the behavior. |
| `black-box` | An unchanged upstream client drives DERPEX and is the assertion. |
| `differential` | The same scenario is replayed against the pinned Go server and DERPEX, and the normalized traces must be equal. |
| `implementation-specific` | A Go implementation detail; the behavior it protects is gated by the cited artifact. |
| `pending` | Release-blocking. Not covered yet. |

| State | Count |
| --- | ---: |
| Total | 69 |
| Ported | 51 |
| Black-box | 9 |
| Differential | 2 |
| Pending (release-blocking) | 3 |
| Implementation-specific | 4 |

| Area | Upstream test | Source | Disposition | Gate/notes |
| --- | --- | --- | --- | --- |
| DERP framing/client | `TestClientRecv` | `derp/client_test.go:27` | `ported` | ported in test/derpex/frame/body_test.exs; malformed short-body cases added |
| DERP framing/client | `TestClientRecvPeerPresent` | `derp/client_test.go:102` | `ported` | ported in test/derpex/frame/body_test.exs with legacy and extension shapes |
| DERP framing/client | `TestClientSendPing` | `derp/client_test.go:189` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendPong` | `derp/client_test.go:206` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendRateLimiting` | `derp/client_test.go:249` | `black-box` | unchanged official client obeys DERPEX ServerInfo token-bucket limits in test/interop/go_client_test.exs |
| DERP framing/client | `TestReadFrameHeader` | `derp/derp_test.go:37` | `ported` | ported in test/derpex/frame_test.exs; extension and all chunk boundaries added |
| DERP framing/client | `TestWriteFrameHeader` | `derp/derp_test.go:96` | `ported` | ported in test/derpex/frame_test.exs; byte-identical vectors |
| DERP framing/client | `TestClientInfoUnmarshal` | `derp/derp_test.go:196` | `ported` | ported in test/derpex/client_info_test.exs; duplicate and field-type cases added |
| DERP framing/client | `TestSendRecv` | `derp/derp_test.go:243` | `differential` | the pinned Go server and DERPEX produce the same relayed-packet and peer-gone trace in test/interop/differential_test.exs |
| DERP framing/client | `TestSendFreeze` | `derp/derp_test.go:464` | `ported` | ported onto real listeners and sockets in test/system/send_freeze_test.exs; a frozen reader is closed by the write timeout while an independent flow keeps delivering |
| DERP framing/client | `TestWatch` | `derp/derp_test.go:875` | `black-box` | unchanged official mesh client covers snapshots and live connect/disconnect updates in test/interop/go_client_test.exs |
| DERP framing/client | `TestWatchAppName` | `derp/derp_test.go:915` | `black-box` | unchanged official mesh client verifies watcher app-name propagation in test/interop/go_client_test.exs |
| DERP framing/client | `TestValidAppName` | `derp/derp_test.go:957` | `ported` | ported in test/derpex/client_info_test.exs; byte-length and ASCII behavior preserved |
| DERP framing/client | `TestServerRepliesToPing` | `derp/derp_test.go:992` | `black-box` | unchanged official client ping/pong gate in test/interop/go_client_test.exs |
| DERP server | `TestSetMeshKey` | `derp/derpserver/derpserver_test.go:45` | `ported` | ported parser and validation cases in test/derpex/mesh_key_test.exs |
| DERP server | `TestIsMeshPeer` | `derp/derpserver/derpserver_test.go:85` | `ported` | ported constant-time trust cases in test/derpex/mesh_key_test.exs |
| DERP server | `TestVerifyClientDisallowedAppNames` | `derp/derpserver/derpserver_test.go:138` | `black-box` | unchanged official clients cover exact app-name rejection and trusted mesh bypass in test/interop/go_client_test.exs |
| DERP server | `TestRecvClientKeyAppName` | `derp/derpserver/derpserver_test.go:169` | `ported` | ported encrypted ClientInfo and app-name validation in test/derpex/handshake_test.exs and test/derpex/client_info_test.exs |
| DERP server | `TestForwarderRegistration` | `derp/derpserver/derpserver_test.go:221` | `ported` | adapted in test/derpex/router_test.exs; duplicate registration, removal, priority, and local precedence preserved |
| DERP server | `TestMultiForwarder` | `derp/derpserver/derpserver_test.go:349` | `ported` | adapted in test/derpex/router_test.exs with 5,000 routes concurrent with repeated forwarder changes |
| DERP server | `TestMetaCert` | `derp/derpserver/derpserver_test.go:405` | `ported` | ported certificate shape in test/derpex/meta_certificate_test.exs plus the official TLS fast-start gate in test/interop/go_client_test.exs |
| DERP server | `TestModifyTLSConfigToAddMetaCert` | `derp/derpserver/derpserver_test.go:441` | `ported` | adapted in test/derpex/certificates_test.exs; concurrent augmentation returns fresh chains without provider mutation |
| DERP server | `TestServerDupClients` | `derp/derpserver/derpserver_test.go:498` | `differential` | duplicate routing is compared step for step against the pinned Go server in test/interop/differential_test.exs; the connection lifecycle cases are in test/derpex/router_test.exs |
| DERP server | `TestLimiter` | `derp/derpserver/derpserver_test.go:747` | `ported` | ported shared burst, refill, zero-rate, disable, and pre-allocation rejection cases in test/derpex/rate_limiter_test.exs and test/derpex/receive_limiter_test.exs |
| DERP server | `TestParseSSOutput` | `derp/derpserver/derpserver_test.go:884` | `ported` | ported in test/derpex/debug/ss_test.exs with IPv4, IPv6, counters, service names, and malformed rows |
| DERP server | `TestServeDebugTrafficUniqueSenders` | `derp/derpserver/derpserver_test.go:895` | `ported` | ported active-route debug lookup and unique-sender reporting in test/derpex/debug/traffic_test.exs |
| DERP server | `TestGetPerClientSendQueueDepth` | `derp/derpserver/derpserver_test.go:924` | `ported` | ported in test/derpex/send_queue_config_test.exs; empty/default and explicit depths preserved |
| DERP server | `TestSenderCardinality` | `derp/derpserver/derpserver_test.go:950` | `ported` | adapted in test/derpex/cardinality_test.exs with duplicate suppression and small-set estimates |
| DERP server | `TestSenderCardinality100` | `derp/derpserver/derpserver_test.go:995` | `ported` | adapted in test/derpex/cardinality_test.exs with the upstream 100-sender tolerance |
| DERP server | `TestSenderCardinalityTracking` | `derp/derpserver/derpserver_test.go:1019` | `ported` | adapted in test/derpex/cardinality_test.exs and test/derpex/writer_test.exs; zero sources are ignored and successful sends are recorded |
| DERP server | `TestPerClientRateLimit` | `derp/derpserver/derpserver_test.go:1093` | `ported` | ported with manual-clock live listener pacing and shutdown cancellation in test/derpex/listener/handler_test.exs |
| DERP server | `TestRateLimitWait` | `derp/derpserver/derpserver_test.go:1231` | `ported` | ported reservation, refill delay, clamp, and cancellation behavior in test/derpex/receive_limiter_test.exs |
| DERP server | `TestUpdateRateLimits` | `derp/derpserver/derpserver_test.go:1304` | `ported` | ported live ordinary and duplicate updates with trusted mesh exemption in test/derpex/rate_controller_test.exs |
| DERP server | `TestLoadRateConfig` | `derp/derpserver/derpserver_test.go:1424` | `ported` | ported upstream JSON shapes, validation, and missing-path failures in test/derpex/rate_config_test.exs |
| DERP server | `TestLoadAndApplyRateConfig` | `derp/derpserver/derpserver_test.go:1480` | `ported` | ported load, normalization, live apply, and disable behavior in test/derpex/rate_config_test.exs and test/derpex/rate_controller_test.exs |
| DERP server | `TestLookupDestHashTrieFastPath` | `derp/derpserver/derpserver_test.go:1582` | `ported` | adapted to the lock-free ETS local-route lookup in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieFallsBackForForwarder` | `derp/derpserver/derpserver_test.go:1610` | `ported` | adapted to the secondary ETS regional-forwarder lookup in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieIgnoresInactiveSet` | `derp/derpserver/derpserver_test.go:1626` | `ported` | DERPEX never publishes inactive local routes; unregister-to-forwarder fallback is covered in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieNoAlloc` | `derp/derpserver/derpserver_test.go:1655` | `implementation-specific` | Go allocation assertion; bench/relay.exs enforces per-flow allocation and p99 latency thresholds through the benchmark smoke in .github/workflows/ci.yml |
| DERP HTTP | `TestSendRecv` | `derp/derphttp/derphttp_test.go:41` | `black-box` | unchanged official clients relay packet boundaries in test/interop/go_client_test.exs |
| DERP HTTP | `TestPing` | `derp/derphttp/derphttp_test.go:181` | `black-box` | unchanged official client gate in test/interop/go_client_test.exs |
| DERP HTTP | `TestBreakWatcherConnRecv` | `derp/derphttp/derphttp_test.go:275` | `ported` | adapted in test/derpex/mesh/client_test.exs; a broken watch socket withdraws routes and reconnects |
| DERP HTTP | `TestBreakWatcherConn` | `derp/derphttp/derphttp_test.go:356` | `ported` | adapted in test/derpex/mesh/client_test.exs; reconnect restores bounded forwarding |
| DERP HTTP | `TestRunWatchConnectionLoopServeConnect` | `derp/derphttp/derphttp_test.go:443` | `ported` | adapted in test/derpex/mesh/client_test.exs; authenticated watch and permanent self-connect detection covered |
| DERP HTTP | `TestLocalAddrNoMutex` | `derp/derphttp/derphttp_test.go:489` | `ported` | adapted in test/derpex/mesh/client_test.exs with a lock-free ETS local-address snapshot and a suspended-client regression test |
| DERP HTTP | `TestProbe` | `derp/derphttp/derphttp_test.go:498` | `ported` | ported in test/derpex/http1_test.exs; both probe paths and upgrade-required behavior |
| DERP HTTP | `TestNotifyError` | `derp/derphttp/derphttp_test.go:519` | `ported` | adapted in test/derpex/mesh/client_test.exs; initial dial errors are reported before retry |
| DERP HTTP | `TestManualDial` | `derp/derphttp/derphttp_test.go:568` | `ported` | adapted in test/derpex/mesh/client_test.exs; private dial host preserves the URL Host and TLS identity |
| DERP HTTP | `TestURLDial` | `derp/derphttp/derphttp_test.go:595` | `ported` | adapted in test/derpex/mesh/client_test.exs with direct URL parsing, dialing, upgrade, and authentication |
| DERP HTTP | `TestConnectThroughProxyHonorsDERPPort` | `derp/derphttp/derphttp_test.go:682` | `ported` | adapted in test/derpex/mesh/client_test.exs with an end-to-end HTTP CONNECT tunnel that records the configured non-default DERP port |
| cmd/derper | `TestUnpublishedDNS` | `cmd/derper/bootstrap_dns_test.go:82` | `ported` | ported selective unpublished responses and no-leak fallback in test/derpex/bootstrap_dns_test.exs |
| cmd/derper | `TestUnpublishedDNSEmptyList` | `cmd/derper/bootstrap_dns_test.go:134` | `ported` | ported empty-list miss behavior and exact unpublished hit/miss counters in test/derpex/bootstrap_dns_test.exs |
| cmd/derper | `TestLookupMetric` | `cmd/derper/bootstrap_dns_test.go:188` | `ported` | ported distinct queried-domain accounting and the upstream 500-name defensive reset in test/derpex/bootstrap_dns_test.exs |
| cmd/derper | `TestRemoteAddrMatchesPercent` | `cmd/derper/bootstrap_dns_test.go:202` | `ported` | ported Go's 128-bit PCG selection with exact vectors and a 65,536-address distribution gate in test/derpex/bootstrap_dns_test.exs |
| cmd/derper | `TestCertIP` | `cmd/derper/cert_test.go:34` | `ported` | ported pure-OTP self-signed IP SAN generation, loading, validation, and persistent reuse in test/derpex/certificates/manual_test.exs |
| cmd/derper | `TestPinnedCertRawIP` | `cmd/derper/cert_test.go:114` | `black-box` | unchanged official region client dials DERPEX by raw IP using the generated sha256-raw DERP-map pin in test/interop/go_client_test.exs |
| cmd/derper | `TestGCPCertMode` | `cmd/derper/cert_test.go:173` | `ported` | ported required EAB/email validation plus padded base64 and unpadded base64url decoding in test/derpex/certificates/mode_test.exs |
| cmd/derper | `TestProdAutocertHostPolicy` | `cmd/derper/derper_test.go:18` | `ported` | ported exact production hostname policy vectors in test/derpex/certificates/mode_test.exs |
| cmd/derper | `TestNoContent` | `cmd/derper/derper_test.go:42` | `ported` | ported all challenge validity cases in test/derpex/http1_test.exs |
| cmd/derper | `TestDeps` | `cmd/derper/derper_test.go:101` | `implementation-specific` | Go dependency graph; the release's runtime application closure is held to an allowlist by scripts/dependency_closure.exs, which mix quality runs |
| cmd/derper | `TestTemplate` | `cmd/derper/derper_test.go:116` | `ported` | ported conditional abuse, policy, disabled-status, and debug homepage sections in test/derpex/home_page_test.exs |
| cmd/derper | `TestIPCertManager` | `cmd/derper/ipcert_test.go:328` | `pending` | upstream drives issuance against a fake ACME server; DERPEX has no RFC 8555 client (PLAN.md section 2.3), so only the self-signed issuer behind DERPEX_IP_CERT_ISSUER=self is wired |
| cmd/derper | `TestIPCertManagerNextProvider` | `cmd/derper/ipcert_test.go:426` | `pending` | the `:next_provider` hook exists but has no production caller — nothing can supply a DNS hostname provider until the ACME client does — so the delegation test in test/derpex/certificates/ip_manager_test.exs exercises a test-only fixture and does not close this row; PLAN.md section 2.3 records ACME as pending |
| cmd/derper | `TestCertModeIPCertsGating` | `cmd/derper/ipcert_test.go:448` | `ported` | ported certificate-mode/IP-host gating in test/derpex/certificates/mode_test.exs and the boot-time refusal of unimplemented modes in test/derpex/certificates/boot_test.exs |
| DERP prober | `TestDerpProber` | `prober/derp_test.go:25` | `pending` | release-blocking mapping not yet implemented |
| DERP prober | `TestRunDerpProbeNodePair` | `prober/derp_test.go:146` | `black-box` | upstream 100 MB transfer and 30-packet in-flight bound run through DERPEX with unchanged official clients in test/interop/go_client_test.exs |
| DERP prober | `Test_packetsForSize` | `prober/derp_test.go:202` | `ported` | ported exact packet counts, total sizes, per-call randomness, and large-payload caching in test/derpex/prober_test.exs |
| XDP | `TestXDP` | `derp/xdp/xdp_linux_test.go:274` | `implementation-specific` | separate Linux XDP path is not in the cmd/derper request path; the pinned oracle job in .github/workflows/ci.yml still runs upstream's own XDP package |
| XDP | `TestCountersMapKey` | `derp/xdp/xdp_linux_test.go:1042` | `implementation-specific` | layout invariant for the unused Go/XDP implementation; the pinned oracle job in .github/workflows/ci.yml still runs upstream's own XDP package |
