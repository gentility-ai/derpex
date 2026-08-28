defmodule Derpex.UpstreamInventory do
  @expected_commit "1e69418c298b680562a2fecd7020f7f58d17d166"

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

  @implementation_specific %{
    {"cmd/derper/derper_test.go", "TestDeps"} =>
      "Go dependency graph; protected behavior maps to the runtime-boundary artifact gate",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieNoAlloc"} =>
      "Go allocation assertion; packet-path allocation and latency benchmarks protect the invariant",
    {"derp/xdp/xdp_linux_test.go", "TestXDP"} =>
      "separate Linux XDP path is not in the cmd/derper request path",
    {"derp/xdp/xdp_linux_test.go", "TestCountersMapKey"} =>
      "layout invariant for the unused Go/XDP implementation"
  }

  @ported %{
    {"derp/client_test.go", "TestClientRecv"} =>
      "ported in test/derpex/frame/body_test.exs; malformed short-body cases added",
    {"derp/client_test.go", "TestClientRecvPeerPresent"} =>
      "ported in test/derpex/frame/body_test.exs with legacy and extension shapes",
    {"derp/client_test.go", "TestClientSendPing"} =>
      "ported in test/derpex/frame/body_test.exs; byte-identical vector",
    {"derp/client_test.go", "TestClientSendPong"} =>
      "ported in test/derpex/frame/body_test.exs; byte-identical vector",
    {"derp/derphttp/derphttp_test.go", "TestProbe"} =>
      "ported in test/derpex/http1_test.exs; both probe paths and upgrade-required behavior",
    {"derp/derphttp/derphttp_test.go", "TestPing"} =>
      "unchanged official client gate in test/interop/go_client_test.exs",
    {"derp/derphttp/derphttp_test.go", "TestSendRecv"} =>
      "unchanged official clients relay packet boundaries in test/interop/go_client_test.exs",
    {"derp/derphttp/derphttp_test.go", "TestBreakWatcherConnRecv"} =>
      "adapted in test/derpex/mesh/client_test.exs; a broken watch socket withdraws routes and reconnects",
    {"derp/derphttp/derphttp_test.go", "TestBreakWatcherConn"} =>
      "adapted in test/derpex/mesh/client_test.exs; reconnect restores bounded forwarding",
    {"derp/derphttp/derphttp_test.go", "TestRunWatchConnectionLoopServeConnect"} =>
      "adapted in test/derpex/mesh/client_test.exs; authenticated watch and permanent self-connect detection covered",
    {"derp/derphttp/derphttp_test.go", "TestNotifyError"} =>
      "adapted in test/derpex/mesh/client_test.exs; initial dial errors are reported before retry",
    {"derp/derphttp/derphttp_test.go", "TestManualDial"} =>
      "adapted in test/derpex/mesh/client_test.exs; private dial host preserves the URL Host and TLS identity",
    {"derp/derphttp/derphttp_test.go", "TestURLDial"} =>
      "adapted in test/derpex/mesh/client_test.exs with direct URL parsing, dialing, upgrade, and authentication",
    {"derp/derpserver/derpserver_test.go", "TestMetaCert"} =>
      "ported certificate shape plus official TLS fast-start gate",
    {"derp/derpserver/derpserver_test.go", "TestModifyTLSConfigToAddMetaCert"} =>
      "adapted in test/derpex/certificates_test.exs; concurrent augmentation returns fresh chains without provider mutation",
    {"derp/derpserver/derpserver_test.go", "TestServerDupClients"} =>
      "ported lifecycle cases and unchanged official last-writer-active client gate",
    {"derp/derpserver/derpserver_test.go", "TestLimiter"} =>
      "ported shared burst, refill, zero-rate, disable, and pre-allocation rejection cases",
    {"derp/derpserver/derpserver_test.go", "TestGetPerClientSendQueueDepth"} =>
      "ported in test/derpex/send_queue_config_test.exs; empty/default and explicit depths preserved",
    {"derp/derpserver/derpserver_test.go", "TestParseSSOutput"} =>
      "ported in test/derpex/debug/ss_test.exs with IPv4, IPv6, counters, service names, and malformed rows",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinality"} =>
      "adapted in test/derpex/cardinality_test.exs with duplicate suppression and small-set estimates",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinality100"} =>
      "adapted in test/derpex/cardinality_test.exs with the upstream 100-sender tolerance",
    {"derp/derpserver/derpserver_test.go", "TestSenderCardinalityTracking"} =>
      "adapted in cardinality and writer tests; zero sources are ignored and successful sends are recorded",
    {"derp/derpserver/derpserver_test.go", "TestSetMeshKey"} =>
      "ported parser and validation cases in test/derpex/mesh_key_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestIsMeshPeer"} =>
      "ported constant-time trust cases in test/derpex/mesh_key_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestVerifyClientDisallowedAppNames"} =>
      "unchanged official clients cover exact app-name rejection and trusted mesh bypass",
    {"derp/derpserver/derpserver_test.go", "TestRecvClientKeyAppName"} =>
      "ported encrypted ClientInfo and app-name validation in handshake and client-info tests",
    {"derp/derpserver/derpserver_test.go", "TestForwarderRegistration"} =>
      "adapted in test/derpex/router_test.exs; duplicate registration, removal, priority, and local precedence preserved",
    {"derp/derpserver/derpserver_test.go", "TestMultiForwarder"} =>
      "adapted in test/derpex/router_test.exs with 5,000 routes concurrent with repeated forwarder changes",
    {"derp/derpserver/derpserver_test.go", "TestPerClientRateLimit"} =>
      "ported with manual-clock live listener pacing and shutdown cancellation",
    {"derp/derpserver/derpserver_test.go", "TestRateLimitWait"} =>
      "ported reservation, refill delay, clamp, and cancellation behavior",
    {"derp/derpserver/derpserver_test.go", "TestUpdateRateLimits"} =>
      "ported live ordinary and duplicate updates with trusted mesh exemption",
    {"derp/derpserver/derpserver_test.go", "TestLoadRateConfig"} =>
      "ported upstream JSON shapes, validation, and missing-path failures",
    {"derp/derpserver/derpserver_test.go", "TestLoadAndApplyRateConfig"} =>
      "ported load, normalization, live apply, and disable behavior",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieFastPath"} =>
      "adapted to the lock-free ETS local-route lookup in test/derpex/router_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieFallsBackForForwarder"} =>
      "adapted to the secondary ETS regional-forwarder lookup in test/derpex/router_test.exs",
    {"derp/derpserver/derpserver_test.go", "TestLookupDestHashTrieIgnoresInactiveSet"} =>
      "DERPEX never publishes inactive local routes; unregister-to-forwarder fallback is covered in test/derpex/router_test.exs",
    {"cmd/derper/derper_test.go", "TestNoContent"} =>
      "ported all challenge validity cases in test/derpex/http1_test.exs",
    {"derp/derp_test.go", "TestClientInfoUnmarshal"} =>
      "ported in test/derpex/client_info_test.exs; duplicate and field-type cases added",
    {"derp/derp_test.go", "TestReadFrameHeader"} =>
      "ported in test/derpex/frame_test.exs; extension and all chunk boundaries added",
    {"derp/derp_test.go", "TestSendFreeze"} =>
      "adapted in test/derpex/writer_test.exs; a saturated frozen writer cannot stop another flow",
    {"derp/derp_test.go", "TestSendRecv"} =>
      "unchanged official clients cover source attribution, empty, and maximum packets",
    {"derp/derp_test.go", "TestServerRepliesToPing"} =>
      "unchanged official client ping/pong gate in test/interop/go_client_test.exs",
    {"derp/derp_test.go", "TestWatch"} =>
      "unchanged official mesh client covers snapshots and live connect/disconnect updates",
    {"derp/derp_test.go", "TestWatchAppName"} =>
      "unchanged official mesh client verifies watcher app-name propagation",
    {"derp/derp_test.go", "TestValidAppName"} =>
      "ported in test/derpex/client_info_test.exs; byte-length and ASCII behavior preserved",
    {"derp/derp_test.go", "TestWriteFrameHeader"} =>
      "ported in test/derpex/frame_test.exs; byte-identical vectors"
  }

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
    cond do
      note = @ported[{file, name}] ->
        {area, file, line, name, "ported", note}

      note = @implementation_specific[{file, name}] ->
        {area, file, line, name, "implementation-specific", note}

      true ->
        {area, file, line, name, "pending", "release-blocking mapping not yet implemented"}
    end
  end

  defp render(tests) do
    pending = Enum.count(tests, &(elem(&1, 4) == "pending"))
    ported = Enum.count(tests, &(elem(&1, 4) == "ported"))
    implementation_specific = length(tests) - pending - ported

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

    | State | Count |
    | --- | ---: |
    | Total | #{length(tests)} |
    | Ported | #{ported} |
    | Pending (release-blocking) | #{pending} |
    | Implementation-specific | #{implementation_specific} |

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
