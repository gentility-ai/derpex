# Upstream compatibility inventory

Generated from Tailscale commit `1e69418c298b680562a2fecd7020f7f58d17d166` by:

```sh
elixir scripts/upstream_inventory.exs ../tailscale --output interop/COVERAGE.md
```

Do not remove a row manually. Change the generator's explicit scope or
disposition map and review that change together with `interop/upstream.lock`.

| State | Count |
| --- | ---: |
| Total | 69 |
| Ported | 64 |
| Pending (release-blocking) | 1 |
| Implementation-specific | 4 |

| Area | Upstream test | Source | Disposition | Gate/notes |
| --- | --- | --- | --- | --- |
| DERP framing/client | `TestClientRecv` | `derp/client_test.go:27` | `ported` | ported in test/derpex/frame/body_test.exs; malformed short-body cases added |
| DERP framing/client | `TestClientRecvPeerPresent` | `derp/client_test.go:102` | `ported` | ported in test/derpex/frame/body_test.exs with legacy and extension shapes |
| DERP framing/client | `TestClientSendPing` | `derp/client_test.go:189` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendPong` | `derp/client_test.go:206` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendRateLimiting` | `derp/client_test.go:249` | `ported` | unchanged official client obeys DERPEX ServerInfo token-bucket limits in test/interop/go_client_test.exs |
| DERP framing/client | `TestReadFrameHeader` | `derp/derp_test.go:37` | `ported` | ported in test/derpex/frame_test.exs; extension and all chunk boundaries added |
| DERP framing/client | `TestWriteFrameHeader` | `derp/derp_test.go:96` | `ported` | ported in test/derpex/frame_test.exs; byte-identical vectors |
| DERP framing/client | `TestClientInfoUnmarshal` | `derp/derp_test.go:196` | `ported` | ported in test/derpex/client_info_test.exs; duplicate and field-type cases added |
| DERP framing/client | `TestSendRecv` | `derp/derp_test.go:243` | `ported` | unchanged official clients cover source attribution, empty, and maximum packets |
| DERP framing/client | `TestSendFreeze` | `derp/derp_test.go:464` | `ported` | adapted in test/derpex/writer_test.exs; a saturated frozen writer cannot stop another flow |
| DERP framing/client | `TestWatch` | `derp/derp_test.go:875` | `ported` | unchanged official mesh client covers snapshots and live connect/disconnect updates |
| DERP framing/client | `TestWatchAppName` | `derp/derp_test.go:915` | `ported` | unchanged official mesh client verifies watcher app-name propagation |
| DERP framing/client | `TestValidAppName` | `derp/derp_test.go:957` | `ported` | ported in test/derpex/client_info_test.exs; byte-length and ASCII behavior preserved |
| DERP framing/client | `TestServerRepliesToPing` | `derp/derp_test.go:992` | `ported` | unchanged official client ping/pong gate in test/interop/go_client_test.exs |
| DERP server | `TestSetMeshKey` | `derp/derpserver/derpserver_test.go:45` | `ported` | ported parser and validation cases in test/derpex/mesh_key_test.exs |
| DERP server | `TestIsMeshPeer` | `derp/derpserver/derpserver_test.go:85` | `ported` | ported constant-time trust cases in test/derpex/mesh_key_test.exs |
| DERP server | `TestVerifyClientDisallowedAppNames` | `derp/derpserver/derpserver_test.go:138` | `ported` | unchanged official clients cover exact app-name rejection and trusted mesh bypass |
| DERP server | `TestRecvClientKeyAppName` | `derp/derpserver/derpserver_test.go:169` | `ported` | ported encrypted ClientInfo and app-name validation in handshake and client-info tests |
| DERP server | `TestForwarderRegistration` | `derp/derpserver/derpserver_test.go:221` | `ported` | adapted in test/derpex/router_test.exs; duplicate registration, removal, priority, and local precedence preserved |
| DERP server | `TestMultiForwarder` | `derp/derpserver/derpserver_test.go:349` | `ported` | adapted in test/derpex/router_test.exs with 5,000 routes concurrent with repeated forwarder changes |
| DERP server | `TestMetaCert` | `derp/derpserver/derpserver_test.go:405` | `ported` | ported certificate shape plus official TLS fast-start gate |
| DERP server | `TestModifyTLSConfigToAddMetaCert` | `derp/derpserver/derpserver_test.go:441` | `ported` | adapted in test/derpex/certificates_test.exs; concurrent augmentation returns fresh chains without provider mutation |
| DERP server | `TestServerDupClients` | `derp/derpserver/derpserver_test.go:498` | `ported` | ported lifecycle cases and unchanged official last-writer-active client gate |
| DERP server | `TestLimiter` | `derp/derpserver/derpserver_test.go:747` | `ported` | ported shared burst, refill, zero-rate, disable, and pre-allocation rejection cases |
| DERP server | `TestParseSSOutput` | `derp/derpserver/derpserver_test.go:884` | `ported` | ported in test/derpex/debug/ss_test.exs with IPv4, IPv6, counters, service names, and malformed rows |
| DERP server | `TestServeDebugTrafficUniqueSenders` | `derp/derpserver/derpserver_test.go:895` | `ported` | ported active-route debug lookup and unique-sender reporting in test/derpex/debug/traffic_test.exs |
| DERP server | `TestGetPerClientSendQueueDepth` | `derp/derpserver/derpserver_test.go:924` | `ported` | ported in test/derpex/send_queue_config_test.exs; empty/default and explicit depths preserved |
| DERP server | `TestSenderCardinality` | `derp/derpserver/derpserver_test.go:950` | `ported` | adapted in test/derpex/cardinality_test.exs with duplicate suppression and small-set estimates |
| DERP server | `TestSenderCardinality100` | `derp/derpserver/derpserver_test.go:995` | `ported` | adapted in test/derpex/cardinality_test.exs with the upstream 100-sender tolerance |
| DERP server | `TestSenderCardinalityTracking` | `derp/derpserver/derpserver_test.go:1019` | `ported` | adapted in cardinality and writer tests; zero sources are ignored and successful sends are recorded |
| DERP server | `TestPerClientRateLimit` | `derp/derpserver/derpserver_test.go:1093` | `ported` | ported with manual-clock live listener pacing and shutdown cancellation |
| DERP server | `TestRateLimitWait` | `derp/derpserver/derpserver_test.go:1231` | `ported` | ported reservation, refill delay, clamp, and cancellation behavior |
| DERP server | `TestUpdateRateLimits` | `derp/derpserver/derpserver_test.go:1304` | `ported` | ported live ordinary and duplicate updates with trusted mesh exemption |
| DERP server | `TestLoadRateConfig` | `derp/derpserver/derpserver_test.go:1424` | `ported` | ported upstream JSON shapes, validation, and missing-path failures |
| DERP server | `TestLoadAndApplyRateConfig` | `derp/derpserver/derpserver_test.go:1480` | `ported` | ported load, normalization, live apply, and disable behavior |
| DERP server | `TestLookupDestHashTrieFastPath` | `derp/derpserver/derpserver_test.go:1582` | `ported` | adapted to the lock-free ETS local-route lookup in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieFallsBackForForwarder` | `derp/derpserver/derpserver_test.go:1610` | `ported` | adapted to the secondary ETS regional-forwarder lookup in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieIgnoresInactiveSet` | `derp/derpserver/derpserver_test.go:1626` | `ported` | DERPEX never publishes inactive local routes; unregister-to-forwarder fallback is covered in test/derpex/router_test.exs |
| DERP server | `TestLookupDestHashTrieNoAlloc` | `derp/derpserver/derpserver_test.go:1655` | `implementation-specific` | Go allocation assertion; packet-path allocation and latency benchmarks protect the invariant |
| DERP HTTP | `TestSendRecv` | `derp/derphttp/derphttp_test.go:41` | `ported` | unchanged official clients relay packet boundaries in test/interop/go_client_test.exs |
| DERP HTTP | `TestPing` | `derp/derphttp/derphttp_test.go:181` | `ported` | unchanged official client gate in test/interop/go_client_test.exs |
| DERP HTTP | `TestBreakWatcherConnRecv` | `derp/derphttp/derphttp_test.go:275` | `ported` | adapted in test/derpex/mesh/client_test.exs; a broken watch socket withdraws routes and reconnects |
| DERP HTTP | `TestBreakWatcherConn` | `derp/derphttp/derphttp_test.go:356` | `ported` | adapted in test/derpex/mesh/client_test.exs; reconnect restores bounded forwarding |
| DERP HTTP | `TestRunWatchConnectionLoopServeConnect` | `derp/derphttp/derphttp_test.go:443` | `ported` | adapted in test/derpex/mesh/client_test.exs; authenticated watch and permanent self-connect detection covered |
| DERP HTTP | `TestLocalAddrNoMutex` | `derp/derphttp/derphttp_test.go:489` | `ported` | adapted with a lock-free ETS local-address snapshot and suspended-client regression test |
| DERP HTTP | `TestProbe` | `derp/derphttp/derphttp_test.go:498` | `ported` | ported in test/derpex/http1_test.exs; both probe paths and upgrade-required behavior |
| DERP HTTP | `TestNotifyError` | `derp/derphttp/derphttp_test.go:519` | `ported` | adapted in test/derpex/mesh/client_test.exs; initial dial errors are reported before retry |
| DERP HTTP | `TestManualDial` | `derp/derphttp/derphttp_test.go:568` | `ported` | adapted in test/derpex/mesh/client_test.exs; private dial host preserves the URL Host and TLS identity |
| DERP HTTP | `TestURLDial` | `derp/derphttp/derphttp_test.go:595` | `ported` | adapted in test/derpex/mesh/client_test.exs with direct URL parsing, dialing, upgrade, and authentication |
| DERP HTTP | `TestConnectThroughProxyHonorsDERPPort` | `derp/derphttp/derphttp_test.go:682` | `ported` | adapted with an end-to-end HTTP CONNECT tunnel that records the configured non-default DERP port |
| cmd/derper | `TestUnpublishedDNS` | `cmd/derper/bootstrap_dns_test.go:82` | `ported` | ported selective unpublished responses and no-leak fallback through /bootstrap-dns |
| cmd/derper | `TestUnpublishedDNSEmptyList` | `cmd/derper/bootstrap_dns_test.go:134` | `ported` | ported empty-list miss behavior and exact unpublished hit/miss counters |
| cmd/derper | `TestLookupMetric` | `cmd/derper/bootstrap_dns_test.go:188` | `ported` | ported distinct queried-domain accounting and the upstream 500-name defensive reset |
| cmd/derper | `TestRemoteAddrMatchesPercent` | `cmd/derper/bootstrap_dns_test.go:202` | `ported` | ported Go's 128-bit PCG selection with exact vectors and 65,536-address distribution gate |
| cmd/derper | `TestCertIP` | `cmd/derper/cert_test.go:34` | `ported` | ported pure-OTP self-signed IP SAN generation, loading, validation, and persistent reuse |
| cmd/derper | `TestPinnedCertRawIP` | `cmd/derper/cert_test.go:114` | `ported` | unchanged official region client dials DERPEX by raw IP using the generated sha256-raw DERP-map pin |
| cmd/derper | `TestGCPCertMode` | `cmd/derper/cert_test.go:173` | `ported` | ported required EAB/email validation plus padded base64 and unpadded base64url decoding |
| cmd/derper | `TestProdAutocertHostPolicy` | `cmd/derper/derper_test.go:18` | `ported` | ported exact production derp*.tailscale.com hostname policy vectors |
| cmd/derper | `TestNoContent` | `cmd/derper/derper_test.go:42` | `ported` | ported all challenge validity cases in test/derpex/http1_test.exs |
| cmd/derper | `TestDeps` | `cmd/derper/derper_test.go:101` | `implementation-specific` | Go dependency graph; protected behavior maps to the runtime-boundary artifact gate |
| cmd/derper | `TestTemplate` | `cmd/derper/derper_test.go:116` | `ported` | ported conditional abuse, policy, disabled-status, and debug homepage sections |
| cmd/derper | `TestIPCertManager` | `cmd/derper/ipcert_test.go:328` | `ported` | ported IPv4/IPv6 issuance with shortlived profile, SNI checks, HTTP-01 routing, and disk-cache reuse |
| cmd/derper | `TestIPCertManagerNextProvider` | `cmd/derper/ipcert_test.go:426` | `ported` | ported DNS-SNI delegation to the next provider without creating an IP certificate order |
| cmd/derper | `TestCertModeIPCertsGating` | `cmd/derper/ipcert_test.go:448` | `ported` | ported certificate-mode/IP-host gating and optional hostname-provider composition |
| DERP prober | `TestDerpProber` | `prober/derp_test.go:25` | `pending` | release-blocking mapping not yet implemented |
| DERP prober | `TestRunDerpProbeNodePair` | `prober/derp_test.go:146` | `ported` | upstream 100 MB transfer and 30-packet in-flight bound run through DERPEX with unchanged official clients |
| DERP prober | `Test_packetsForSize` | `prober/derp_test.go:202` | `ported` | ported exact packet counts, total sizes, per-call randomness, and large-payload caching in test/derpex/prober_test.exs |
| XDP | `TestXDP` | `derp/xdp/xdp_linux_test.go:274` | `implementation-specific` | separate Linux XDP path is not in the cmd/derper request path |
| XDP | `TestCountersMapKey` | `derp/xdp/xdp_linux_test.go:1042` | `implementation-specific` | layout invariant for the unused Go/XDP implementation |
