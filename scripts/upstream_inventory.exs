defmodule Derpex.UpstreamInventory do
  @expected_commit "1e69418c298b680562a2fecd7020f7f58d17d166"
  @repository Path.expand("..", __DIR__)

  @areas [
    {"DERP framing/client", ["derp/client_test.go", "derp/derp_test.go"]},
    {"DERP server", ["derp/derpserver/derpserver_test.go"]},
    {"DERP HTTP", ["derp/derphttp/derphttp_test.go"]},
    {"cmd/derper",
     [
       "cmd/derper/bootstrap_dns_test.go",
       "cmd/derper/cert_test.go",
       "cmd/derper/derper_test.go",
       "cmd/derper/ipcert_test.go"
     ]},
    {"DERP prober", ["prober/derp_test.go"]},
    {"XDP", ["derp/xdp/xdp_linux_test.go"]}
  ]

  # Anything in a note that looks like a repository path. Every non-pending row
  # has to name at least one, and each one has to exist, so a row cannot claim
  # coverage that no file in this repository provides.
  @citation ~r{(?:test|bench|scripts|interop|lib|native|\.github)/[A-Za-z0-9_./-]*[A-Za-z0-9_]}

  # A row DERPEX satisfies with its own tests.
  @ported %{
    {"derp/client_test.go", "TestClientRecv"} =>
      "ported in test/derpex/frame/body_test.exs; malformed short-body cases added",
    {"derp/client_test.go", "TestClientRecvPeerPresent"} =>
      "ported in test/derpex/frame/body_test.exs with legacy and extension shapes",
    {"derp/client_test.go", "TestClientSendPing"} =>
      "ported in test/derpex/frame/body_test.exs; byte-identical vector",
    {"derp/client_test.go", "TestClientSendPong"} =>
      "ported in test/derpex/frame/body_test.exs; byte-identical vector",
    {"derp/derp_test.go", "TestClientInfoUnmarshal"} =>
      "ported in test/derpex/client_info_test.exs; duplicate and field-type cases added",
    {"derp/derp_test.go", "TestReadFrameHeader"} =>
      "ported in test/derpex/frame_test.exs; extension and all chunk boundaries added",
    {"derp/derp_test.go", "TestSendFreeze"} =>
      "ported onto real listeners and sockets in test/system/send_freeze_test.exs; a frozen reader is closed by the write timeout while an independent flow keeps delivering",
    {"derp/derp_test.go", "TestValidAppName"} =>
      "ported in test/derpex/client_info_test.exs; byte-length and ASCII behavior preserved",
    {"derp/derp_test.go", "TestWriteFrameHeader"} =>
      "ported in test/derpex/frame_test.exs; byte-identical vectors",
    {"derp/derphttp/derphttp_test.go", "TestProbe"} =>
      "ported in test/derpex/http1_test.exs; both probe paths and upgrade-required behavior",
    {"derp/derphttp/derphttp_test.go", "TestBreakWatcherConnRecv"} =>
      "adapted in test/derpex/mesh/client_test.exs; a broken watch socket withdraws routes and reconnects",
    {"derp/derphttp/derphttp_test.go", "TestBreakWatcherConn"} =>
      "adapted in test/derpex/mesh/client_test.exs; reconnect restores bounded forwarding",
    {"derp/derphttp/derphttp_test.go", "TestRunWatchConnectionLoopServeConnect"} =>
      "adapted in test/derpex/mesh/client_test.exs; authenticated watch and permanent self-connect detection covered",
    {"derp/derphttp/derphttp_test.go", "TestLocalAddrNoMutex"} =>
      "adapted in test/derpex/mesh/client_test.exs with a lock-free ETS local-address snapshot and a suspended-client regression test",
    {"derp/derphttp/derphttp_test.go", "TestNotifyError"} =>
      "adapted in test/derpex/mesh/client_test.exs; initial dial errors are reported before retry",
    {"derp/derphttp/derphttp_test.go", "TestManualDial"} =>
      "adapted in test/derpex/mesh/client_test.exs; private dial host preserves the URL Host and TLS identity",
    {"derp/derphttp/derphttp_test.go", "TestURLDial"} =>
      "adapted in test/derpex/mesh/client_test.exs with direct URL parsing, dialing, upgrade, and authentication",
    {"derp/derphttp/derphttp_test.go", "TestConnectThroughProxyHonorsDERPPort"} =>
      "adapted in test/derpex/mesh/client_test.exs with an end-to-end HTTP CONNECT tunnel that records the configured non-default DERP port",
    {"derp/derpserver/derpserver_test.go", "TestMetaCert"} =>
      "ported certificate shape in test/derpex/meta_certificate_test.exs plus the official TLS fast-start gate in test/interop/go_client_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestModifyTLSConfigToAddMetaCert"} =>
      "adapted in test/derpex/certificates_test.exs; concurrent augmentation returns fresh chains without provider mutation",
    {"derp/derpserver/derpserver_test.go", "TestLimiter"} =>
      "ported shared burst, refill, zero-rate, disable, and pre-allocation rejection cases in test/derpex/rate_limiter_test.exs and test/derpex/receive_limiter_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestGetPerClientSendQueueDepth"} =>
      "ported in test/derpex/send_queue_config_test.exs; empty/default and explicit depths preserved",
    {"derp/derpserver/derpserver_test.go", "TestParseSSOutput"} =>
      "ported in test/derpex/debug/ss_test.exs with IPv4, IPv6, counters, service names, and malformed rows",
    {"derp/derpserver/derpserver_test.go", "TestServeDebugTrafficUniqueSenders"} =>
      "ported active-route debug lookup and unique-sender reporting in test/derpex/debug/traffic_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinality"} =>
      "adapted in test/derpex/cardinality_test.exs with duplicate suppression and small-set estimates",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinality100"} =>
      "adapted in test/derpex/cardinality_test.exs with the upstream 100-sender tolerance",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinalityTracking"} =>
      "adapted in test/derpex/cardinality_test.exs and test/derpex/writer_test.exs; zero sources are ignored and successful sends are recorded",
    {"derp/derpserver/derpserver_test.go", "TestSetMeshKey"} =>
      "ported parser and validation cases in test/derpex/mesh_key_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestIsMeshPeer"} =>
      "ported constant-time trust cases in test/derpex/mesh_key_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestRecvClientKeyAppName"} =>
      "ported encrypted ClientInfo and app-name validation in test/derpex/handshake_test.exs and test/derpex/client_info_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestForwarderRegistration"} =>
      "adapted in test/derpex/router_test.exs; duplicate registration, removal, priority, and local precedence preserved",
    {"derp/derpserver/derpserver_test.go", "TestMultiForwarder"} =>
      "adapted in test/derpex/router_test.exs with 5,000 routes concurrent with repeated forwarder changes",
    {"derp/derpserver/derpserver_test.go", "TestPerClientRateLimit"} =>
      "ported with manual-clock live listener pacing and shutdown cancellation in test/derpex/listener/handler_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestRateLimitWait"} =>
      "ported reservation, refill delay, clamp, and cancellation behavior in test/derpex/receive_limiter_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestUpdateRateLimits"} =>
      "ported live ordinary and duplicate updates with trusted mesh exemption in test/derpex/rate_controller_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLoadRateConfig"} =>
      "ported upstream JSON shapes, validation, and missing-path failures in test/derpex/rate_config_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLoadAndApplyRateConfig"} =>
      "ported load, normalization, live apply, and disable behavior in test/derpex/rate_config_test.exs and test/derpex/rate_controller_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieFastPath"} =>
      "adapted to the lock-free ETS local-route lookup in test/derpex/router_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieFallsBackForForwarder"} =>
      "adapted to the secondary ETS regional-forwarder lookup in test/derpex/router_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieIgnoresInactiveSet"} =>
      "DERPEX never publishes inactive local routes; unregister-to-forwarder fallback is covered in test/derpex/router_test.exs",
    {"cmd/derper/bootstrap_dns_test.go", "TestUnpublishedDNS"} =>
      "ported selective unpublished responses and no-leak fallback in test/derpex/bootstrap_dns_test.exs",
    {"cmd/derper/bootstrap_dns_test.go", "TestUnpublishedDNSEmptyList"} =>
      "ported empty-list miss behavior and exact unpublished hit/miss counters in test/derpex/bootstrap_dns_test.exs",
    {"cmd/derper/bootstrap_dns_test.go", "TestLookupMetric"} =>
      "ported distinct queried-domain accounting and the upstream 500-name defensive reset in test/derpex/bootstrap_dns_test.exs",
    {"cmd/derper/bootstrap_dns_test.go", "TestRemoteAddrMatchesPercent"} =>
      "ported Go's 128-bit PCG selection with exact vectors and a 65,536-address distribution gate in test/derpex/bootstrap_dns_test.exs",
    {"cmd/derper/cert_test.go", "TestGCPCertMode"} =>
      "ported required EAB/email validation plus padded base64 and unpadded base64url decoding in test/derpex/certificates/mode_test.exs",
    {"cmd/derper/cert_test.go", "TestCertIP"} =>
      "ported pure-OTP self-signed IP SAN generation, loading, validation, and persistent reuse in test/derpex/certificates/manual_test.exs",
    {"cmd/derper/derper_test.go", "TestProdAutocertHostPolicy"} =>
      "ported exact production hostname policy vectors in test/derpex/certificates/mode_test.exs",
    {"cmd/derper/derper_test.go", "TestTemplate"} =>
      "ported conditional abuse, policy, disabled-status, and debug homepage sections in test/derpex/home_page_test.exs",
    {"cmd/derper/derper_test.go", "TestNoContent"} =>
      "ported all challenge validity cases in test/derpex/http1_test.exs",
    {"cmd/derper/ipcert_test.go", "TestCertModeIPCertsGating"} =>
      "ported certificate-mode/IP-host gating in test/derpex/certificates/mode_test.exs and the boot-time refusal of unimplemented modes in test/derpex/certificates/boot_test.exs",
    {"prober/derp_test.go", "TestDerpProber"} =>
      "ported dynamic region filtering, probe inventory, and add/remove reconciliation in test/derpex/prober_test.exs",
    {"prober/derp_test.go", "Test_packetsForSize"} =>
      "ported exact packet counts, total sizes, per-call randomness, and large-payload caching in test/derpex/prober_test.exs"
  }

  # A row an unchanged upstream client satisfies by driving DERPEX directly.
  # DERPEX writes no equivalent of the upstream test; the official client is
  # the assertion, so the citation is always an interoperability test.
  @black_box %{
    {"derp/client_test.go", "TestClientSendRateLimiting"} =>
      "unchanged official client obeys DERPEX ServerInfo token-bucket limits in test/interop/go_client_test.exs",
    {"derp/derp_test.go", "TestServerRepliesToPing"} =>
      "unchanged official client ping/pong gate in test/interop/go_client_test.exs",
    {"derp/derp_test.go", "TestWatch"} =>
      "unchanged official mesh client covers snapshots and live connect/disconnect updates in test/interop/go_client_test.exs",
    {"derp/derp_test.go", "TestWatchAppName"} =>
      "unchanged official mesh client verifies watcher app-name propagation in test/interop/go_client_test.exs",
    {"derp/derphttp/derphttp_test.go", "TestSendRecv"} =>
      "unchanged official clients relay packet boundaries in test/interop/go_client_test.exs",
    {"derp/derphttp/derphttp_test.go", "TestPing"} =>
      "unchanged official client gate in test/interop/go_client_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestVerifyClientDisallowedAppNames"} =>
      "unchanged official clients cover exact app-name rejection and trusted mesh bypass in test/interop/go_client_test.exs",
    {"cmd/derper/cert_test.go", "TestPinnedCertRawIP"} =>
      "unchanged official region client dials DERPEX by raw IP using the generated sha256-raw DERP-map pin in test/interop/go_client_test.exs",
    {"prober/derp_test.go", "TestRunDerpProbeNodePair"} =>
      "upstream 100 MB transfer and 30-packet in-flight bound run through DERPEX with unchanged official clients in test/interop/go_client_test.exs"
  }

  # A row the trace comparison settles: the same scenario is replayed against
  # the pinned Go server and against DERPEX, and the normalized traces must be
  # equal. Nothing here is asserted from a hardcoded expectation.
  @differential %{
    {"derp/derp_test.go", "TestSendRecv"} =>
      "the pinned Go server and DERPEX produce the same relayed-packet and peer-gone trace in test/interop/differential_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestServerDupClients"} =>
      "duplicate routing is compared step for step against the pinned Go server in test/interop/differential_test.exs; the connection lifecycle cases are in test/derpex/router_test.exs"
  }

  # Rows that stay release-blocking until the work they name exists. Both
  # ipcert rows drive an ACME issuance flow against a fake ACME server; DERPEX
  # has no RFC 8555 client yet, so its IP certificate manager is only reachable
  # behind DERPEX_IP_CERT_ISSUER=self and cannot claim the port.
  @pending %{
    {"cmd/derper/ipcert_test.go", "TestIPCertManager"} =>
      "upstream drives issuance against a fake ACME server; DERPEX has no RFC 8555 client (PLAN.md section 2.3), so only the self-signed issuer behind DERPEX_IP_CERT_ISSUER=self is wired",
    {"cmd/derper/ipcert_test.go", "TestIPCertManagerNextProvider"} =>
      "next-provider delegation is only observable once an ACME hostname provider exists; PLAN.md section 2.3 records ACME as pending"
  }

  # A row about a Go implementation detail. The behavior it protects is still
  # gated here, so each of these cites the artifact that gates it.
  @implementation_specific %{
    {"cmd/derper/derper_test.go", "TestDeps"} =>
      "Go dependency graph; the release's runtime application closure is held to an allowlist by scripts/dependency_closure.exs, which mix quality runs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieNoAlloc"} =>
      "Go allocation assertion; bench/relay.exs enforces per-flow allocation and p99 latency thresholds through the benchmark smoke in .github/workflows/ci.yml",
    {"derp/xdp/xdp_linux_test.go", "TestXDP"} =>
      "separate Linux XDP path is not in the cmd/derper request path; the pinned oracle job in .github/workflows/ci.yml still runs upstream's own XDP package",
    {"derp/xdp/xdp_linux_test.go", "TestCountersMapKey"} =>
      "layout invariant for the unused Go/XDP implementation; the pinned oracle job in .github/workflows/ci.yml still runs upstream's own XDP package"
  }

  @dispositions [
    {"ported", @ported},
    {"black-box", @black_box},
    {"differential", @differential},
    {"pending", @pending},
    {"implementation-specific", @implementation_specific}
  ]

  def main(args) do
    {options, positional, invalid} =
      OptionParser.parse(args, strict: [output: :string], aliases: [o: :output])

    case {positional, invalid, options[:output]} do
      {[upstream], [], output} when is_binary(output) ->
        upstream = Path.expand(upstream)
        verify_commit!(upstream)
        tests = collect_tests!(upstream)

        unless length(tests) == 69 do
          abort("expected 69 relevant tests, found #{length(tests)}")
        end

        verify_citations!(tests)
        File.write!(output, render(tests))
        IO.puts("wrote #{output} with #{length(tests)} tests")

      _other ->
        abort("usage: elixir scripts/upstream_inventory.exs UPSTREAM --output PATH")
    end
  end

  defp verify_commit!(upstream) do
    case System.cmd("git", ["-C", upstream, "rev-parse", "HEAD"], stderr_to_stdout: true) do
      {commit, 0} ->
        if String.trim(commit) != @expected_commit do
          abort(
            "upstream commit mismatch: expected #{@expected_commit}, got #{String.trim(commit)}"
          )
        end

      {message, status} ->
        abort("could not inspect upstream checkout (#{status}): #{String.trim(message)}")
    end
  end

  # A disposition is a claim about DERPEX, so every one of them has to name a
  # file in this repository that carries the claim, and that file has to be
  # there. `ported`, `black-box`, and `differential` additionally have to name
  # a test; `pending` claims nothing and needs nothing.
  defp verify_citations!(tests) do
    problems =
      Enum.flat_map(tests, fn {_area, _file, _line, name, disposition, note} ->
        citations = citations(note)
        missing = Enum.reject(citations, &File.exists?(Path.join(@repository, &1)))
        tests_cited = Enum.filter(citations, &test_file?/1)

        cond do
          disposition == "pending" -> []
          missing != [] -> ["#{name}: cites missing #{Enum.join(missing, ", ")}"]
          citations == [] -> ["#{name}: #{disposition} row cites no repository path"]
          disposition == "implementation-specific" -> []
          tests_cited == [] -> ["#{name}: #{disposition} row cites no DERPEX test file"]
          true -> []
        end
      end)

    unless problems == [] do
      abort("inventory citations are not satisfied:\n  " <> Enum.join(problems, "\n  "))
    end
  end

  defp citations(note) do
    @citation |> Regex.scan(note) |> Enum.map(&hd/1) |> Enum.uniq()
  end

  defp test_file?(path) do
    String.starts_with?(path, "test/") and String.ends_with?(path, ".exs")
  end

  defp collect_tests!(upstream) do
    Enum.flat_map(@areas, fn {area, files} ->
      Enum.flat_map(files, fn file ->
        path = Path.join(upstream, file)

        path
        |> File.stream!()
        |> Enum.with_index(1)
        |> Enum.flat_map(fn {line, number} ->
          case Regex.run(~r/^func (Test[A-Za-z0-9_]+)\(/, line) do
            [_, name] -> [row(area, file, number, name)]
            nil -> []
          end
        end)
      end)
    end)
  end

  defp row(area, file, line, name) do
    case Enum.find_value(@dispositions, fn {disposition, notes} ->
           case notes[{file, name}] do
             nil -> nil
             note -> {disposition, note}
           end
         end) do
      {disposition, note} -> {area, file, line, name, disposition, note}
      nil -> {area, file, line, name, "pending", "release-blocking mapping not yet implemented"}
    end
  end

  defp render(tests) do
    counts =
      Map.new(@dispositions, fn {disposition, _notes} ->
        {disposition, Enum.count(tests, &(elem(&1, 4) == disposition))}
      end)

    rows =
      Enum.map_join(tests, "\n", fn {area, file, line, name, disposition, note} ->
        "| #{area} | `#{name}` | `#{file}:#{line}` | `#{disposition}` | #{note} |"
      end)

    """
    # Upstream compatibility inventory

    Generated from Tailscale commit `#{@expected_commit}` by:

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
    | Total | #{length(tests)} |
    | Ported | #{counts["ported"]} |
    | Black-box | #{counts["black-box"]} |
    | Differential | #{counts["differential"]} |
    | Pending (release-blocking) | #{counts["pending"]} |
    | Implementation-specific | #{counts["implementation-specific"]} |

    | Area | Upstream test | Source | Disposition | Gate/notes |
    | --- | --- | --- | --- | --- |
    #{rows}
    """
  end

  defp abort(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end
end

Derpex.UpstreamInventory.main(System.argv())
