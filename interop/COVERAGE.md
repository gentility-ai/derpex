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
| Ported | 17 |
| Pending (release-blocking) | 48 |
| Implementation-specific | 4 |

| Area | Upstream test | Source | Disposition | Gate/notes |
| --- | --- | --- | --- | --- |
| DERP framing/client | `TestClientRecv` | `derp/client_test.go:27` | `ported` | ported in test/derpex/frame/body_test.exs; malformed short-body cases added |
| DERP framing/client | `TestClientRecvPeerPresent` | `derp/client_test.go:102` | `ported` | ported in test/derpex/frame/body_test.exs with legacy and extension shapes |
| DERP framing/client | `TestClientSendPing` | `derp/client_test.go:189` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendPong` | `derp/client_test.go:206` | `ported` | ported in test/derpex/frame/body_test.exs; byte-identical vector |
| DERP framing/client | `TestClientSendRateLimiting` | `derp/client_test.go:249` | `pending` | release-blocking mapping not yet implemented |
| DERP framing/client | `TestReadFrameHeader` | `derp/derp_test.go:37` | `ported` | ported in test/derpex/frame_test.exs; extension and all chunk boundaries added |
| DERP framing/client | `TestWriteFrameHeader` | `derp/derp_test.go:96` | `ported` | ported in test/derpex/frame_test.exs; byte-identical vectors |
| DERP framing/client | `TestClientInfoUnmarshal` | `derp/derp_test.go:196` | `ported` | ported in test/derpex/client_info_test.exs; duplicate and field-type cases added |
| DERP framing/client | `TestSendRecv` | `derp/derp_test.go:243` | `ported` | unchanged official clients cover source attribution, empty, and maximum packets |
| DERP framing/client | `TestSendFreeze` | `derp/derp_test.go:464` | `ported` | adapted in test/derpex/writer_test.exs; a saturated frozen writer cannot stop another flow |
| DERP framing/client | `TestWatch` | `derp/derp_test.go:875` | `pending` | release-blocking mapping not yet implemented |
| DERP framing/client | `TestWatchAppName` | `derp/derp_test.go:915` | `pending` | release-blocking mapping not yet implemented |
| DERP framing/client | `TestValidAppName` | `derp/derp_test.go:957` | `ported` | ported in test/derpex/client_info_test.exs; byte-length and ASCII behavior preserved |
| DERP framing/client | `TestServerRepliesToPing` | `derp/derp_test.go:992` | `ported` | unchanged official client ping/pong gate in test/interop/go_client_test.exs |
| DERP server | `TestSetMeshKey` | `derp/derpserver/derpserver_test.go:45` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestIsMeshPeer` | `derp/derpserver/derpserver_test.go:85` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestVerifyClientDisallowedAppNames` | `derp/derpserver/derpserver_test.go:138` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestRecvClientKeyAppName` | `derp/derpserver/derpserver_test.go:169` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestForwarderRegistration` | `derp/derpserver/derpserver_test.go:221` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestMultiForwarder` | `derp/derpserver/derpserver_test.go:349` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestMetaCert` | `derp/derpserver/derpserver_test.go:405` | `ported` | ported certificate shape plus official TLS fast-start gate |
| DERP server | `TestModifyTLSConfigToAddMetaCert` | `derp/derpserver/derpserver_test.go:441` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestServerDupClients` | `derp/derpserver/derpserver_test.go:498` | `ported` | ported lifecycle cases and unchanged official last-writer-active client gate |
| DERP server | `TestLimiter` | `derp/derpserver/derpserver_test.go:747` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestParseSSOutput` | `derp/derpserver/derpserver_test.go:884` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestServeDebugTrafficUniqueSenders` | `derp/derpserver/derpserver_test.go:895` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestGetPerClientSendQueueDepth` | `derp/derpserver/derpserver_test.go:924` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestSenderCardinality` | `derp/derpserver/derpserver_test.go:950` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestSenderCardinality100` | `derp/derpserver/derpserver_test.go:995` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestSenderCardinalityTracking` | `derp/derpserver/derpserver_test.go:1019` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestPerClientRateLimit` | `derp/derpserver/derpserver_test.go:1093` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestRateLimitWait` | `derp/derpserver/derpserver_test.go:1231` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestUpdateRateLimits` | `derp/derpserver/derpserver_test.go:1304` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLoadRateConfig` | `derp/derpserver/derpserver_test.go:1424` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLoadAndApplyRateConfig` | `derp/derpserver/derpserver_test.go:1480` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLookupDestHashTrieFastPath` | `derp/derpserver/derpserver_test.go:1582` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLookupDestHashTrieFallsBackForForwarder` | `derp/derpserver/derpserver_test.go:1610` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLookupDestHashTrieIgnoresInactiveSet` | `derp/derpserver/derpserver_test.go:1626` | `pending` | release-blocking mapping not yet implemented |
| DERP server | `TestLookupDestHashTrieNoAlloc` | `derp/derpserver/derpserver_test.go:1655` | `implementation-specific` | Go allocation assertion; packet-path allocation and latency benchmarks protect the invariant |
| DERP HTTP | `TestSendRecv` | `derp/derphttp/derphttp_test.go:41` | `ported` | unchanged official clients relay packet boundaries in test/interop/go_client_test.exs |
| DERP HTTP | `TestPing` | `derp/derphttp/derphttp_test.go:181` | `ported` | unchanged official client gate in test/interop/go_client_test.exs |
| DERP HTTP | `TestBreakWatcherConnRecv` | `derp/derphttp/derphttp_test.go:275` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestBreakWatcherConn` | `derp/derphttp/derphttp_test.go:356` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestRunWatchConnectionLoopServeConnect` | `derp/derphttp/derphttp_test.go:443` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestLocalAddrNoMutex` | `derp/derphttp/derphttp_test.go:489` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestProbe` | `derp/derphttp/derphttp_test.go:498` | `ported` | ported in test/derpex/http1_test.exs; both probe paths and upgrade-required behavior |
| DERP HTTP | `TestNotifyError` | `derp/derphttp/derphttp_test.go:519` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestManualDial` | `derp/derphttp/derphttp_test.go:568` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestURLDial` | `derp/derphttp/derphttp_test.go:595` | `pending` | release-blocking mapping not yet implemented |
| DERP HTTP | `TestConnectThroughProxyHonorsDERPPort` | `derp/derphttp/derphttp_test.go:682` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestUnpublishedDNS` | `cmd/derper/bootstrap_dns_test.go:82` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestUnpublishedDNSEmptyList` | `cmd/derper/bootstrap_dns_test.go:134` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestLookupMetric` | `cmd/derper/bootstrap_dns_test.go:188` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestRemoteAddrMatchesPercent` | `cmd/derper/bootstrap_dns_test.go:202` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestCertIP` | `cmd/derper/cert_test.go:34` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestPinnedCertRawIP` | `cmd/derper/cert_test.go:114` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestGCPCertMode` | `cmd/derper/cert_test.go:173` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestProdAutocertHostPolicy` | `cmd/derper/derper_test.go:18` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestNoContent` | `cmd/derper/derper_test.go:42` | `ported` | ported all challenge validity cases in test/derpex/http1_test.exs |
| cmd/derper | `TestDeps` | `cmd/derper/derper_test.go:101` | `implementation-specific` | Go dependency graph; protected behavior maps to the runtime-boundary artifact gate |
| cmd/derper | `TestTemplate` | `cmd/derper/derper_test.go:116` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestIPCertManager` | `cmd/derper/ipcert_test.go:328` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestIPCertManagerNextProvider` | `cmd/derper/ipcert_test.go:426` | `pending` | release-blocking mapping not yet implemented |
| cmd/derper | `TestCertModeIPCertsGating` | `cmd/derper/ipcert_test.go:448` | `pending` | release-blocking mapping not yet implemented |
| DERP prober | `TestDerpProber` | `prober/derp_test.go:25` | `pending` | release-blocking mapping not yet implemented |
| DERP prober | `TestRunDerpProbeNodePair` | `prober/derp_test.go:146` | `pending` | release-blocking mapping not yet implemented |
| DERP prober | `Test_packetsForSize` | `prober/derp_test.go:202` | `pending` | release-blocking mapping not yet implemented |
| XDP | `TestXDP` | `derp/xdp/xdp_linux_test.go:274` | `implementation-specific` | separate Linux XDP path is not in the cmd/derper request path |
| XDP | `TestCountersMapKey` | `derp/xdp/xdp_linux_test.go:1042` | `implementation-specific` | layout invariant for the unused Go/XDP implementation |
