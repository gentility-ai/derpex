defmodule Derpex.Interop.DifferentialTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  @moduletag :differential
  @moduletag timeout: 180_000

  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Secret
  alias Derpex.Test.UpstreamPin

  @mesh_key_hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  @operations_token "differential-trace-operations-token"

  test "pinned Go server and DERPEX produce the same normalized semantic trace" do
    upstream = UpstreamPin.checkout!()

    {server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 4,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(Base.decode16!(@mesh_key_hex, case: :mixed)),
          operations: [enabled: true, token: @operations_token]
        ]
      )

    on_exit(fn -> if Process.alive?(server), do: Process.exit(server, :shutdown) end)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/differential_trace.go", __DIR__)

    oracle = run_trace!(upstream, helper, ["oracle", @mesh_key_hex])

    derpex =
      run_trace!(upstream, helper, [
        "http://127.0.0.1:#{port}/derp",
        @mesh_key_hex,
        "http://127.0.0.1:#{port}/metrics",
        @operations_token
      ])

    # Compare scenario by scenario and step by step first, so a divergence names
    # the step that produced it instead of printing two whole traces.
    assert_same_shape(derpex, oracle)
    assert derpex == oracle

    assert_non_vacuous(oracle)
  end

  defp assert_same_shape(derpex, oracle) do
    assert Enum.map(derpex["scenarios"], & &1["name"]) ==
             Enum.map(oracle["scenarios"], & &1["name"])

    for {derpex_scenario, oracle_scenario} <-
          Enum.zip(derpex["scenarios"], oracle["scenarios"]) do
      name = oracle_scenario["name"]

      assert Enum.map(derpex_scenario["steps"], & &1["step"]) ==
               Enum.map(oracle_scenario["steps"], & &1["step"]),
             "#{name}: step sequence differs"

      for {derpex_step, oracle_step} <-
            Enum.zip(derpex_scenario["steps"], oracle_scenario["steps"]) do
        step = oracle_step["step"]

        assert derpex_step["counters"] == oracle_step["counters"],
               "#{name}/#{step}: counter deltas differ"

        assert derpex_step["events"] == oracle_step["events"],
               "#{name}/#{step}: observed frames differ"

        assert derpex_step["saturating"] == oracle_step["saturating"],
               "#{name}/#{step}: comparison policy differs"
      end
    end
  end

  # Two identical all-zero traces would compare equal without proving anything,
  # so the oracle's own run has to have moved the counters its scenarios claim.
  defp assert_non_vacuous(oracle) do
    assert Enum.map(oracle["scenarios"], & &1["name"]) ==
             ["relay_and_drops", "duplicate_keys", "watch_presence"]

    assert counter(oracle, "relay_and_drops", "relay_payloads", "derp_packets_sent") == 3
    assert counter(oracle, "relay_and_drops", "ping_pong", "derp_got_ping") == 1
    assert counter(oracle, "relay_and_drops", "ping_pong", "derp_sent_pong") == 1

    for {step, kind} <- [
          {"unknown_destination_disco", "disco"},
          {"unknown_destination_plain", "other"}
        ] do
      assert counter(oracle, "relay_and_drops", step, dropped(kind, "unknown_dest")) == 1
    end

    # Only a disco packet earns a not-here reply on either server.
    assert counter(
             oracle,
             "relay_and_drops",
             "unknown_destination_disco",
             "derp_peer_gone_not_here_frames"
           ) == 1

    assert counter(
             oracle,
             "relay_and_drops",
             "unknown_destination_plain",
             "derp_peer_gone_not_here_frames"
           ) == 0

    # Five probes, one allowance of three: every probe is dropped as an unknown
    # destination, but only the first three are answered with a not-here frame.
    assert counter(
             oracle,
             "relay_and_drops",
             "rate_limited_not_here",
             dropped("disco", "unknown_dest")
           ) == 5

    assert counter(
             oracle,
             "relay_and_drops",
             "rate_limited_not_here",
             "derp_peer_gone_not_here_frames"
           ) == 3

    assert Enum.map(events(oracle, "relay_and_drops", "rate_limited_not_here"), & &1["kind"]) ==
             ["peer_gone", "peer_gone", "peer_gone"]

    # TestSendRecv's wantActive walk: 0 -> 1 -> 1 -> 0 -> 0 -> 1, then the home
    # client disconnects and takes the gauge back down with it.
    assert Enum.map(
             [
               "home_preferred_on",
               "home_preferred_repeat_on",
               "home_preferred_off",
               "home_preferred_repeat_off",
               "home_second_preferred_on",
               "close_second"
             ],
             &counter(oracle, "relay_and_drops", &1, "derp_current_home_connections")
           ) == [1, 0, -1, 0, 1, -1]

    # Both queues overrun. These cells are sign-compared, so 1 means "drops
    # happened" rather than "one packet was dropped".
    for kind <- ["disco", "other"] do
      assert counter(
               oracle,
               "relay_and_drops",
               "flood_stalled_recipient",
               dropped(kind, "queue_head")
             ) >
               0
    end

    assert counter(oracle, "relay_and_drops", "flood_stalled_recipient", "derp_packets_received") ==
             192

    # 32-deep ordinary queue + 32-deep disco queue + the packet in flight.
    assert counter(oracle, "relay_and_drops", "drain_stalled_recipient", "derp_packets_sent") ==
             65

    assert counter(oracle, "relay_and_drops", "close_first", "derp_peer_gone_disconnected_frames") ==
             1

    for {metric, expected} <- [
          {"derp_total_dup_client_conns", 1},
          {"derp_current_dup_client_keys", 1},
          {"derp_current_dup_client_conns", 2}
        ] do
      assert counter(oracle, "duplicate_keys", "connect_duplicates", metric) == expected
    end

    assert counter(
             oracle,
             "watch_presence",
             "forward_unknown_destination",
             "derp_packets_forwarded_in"
           ) ==
             2

    for kind <- ["disco", "other"] do
      assert counter(
               oracle,
               "watch_presence",
               "forward_unknown_destination",
               dropped(kind, "unknown_dest_on_fwd")
             ) == 1
    end

    assert counter(
             oracle,
             "watch_presence",
             "close_second_regular",
             "derp_peer_gone_disconnected_frames"
           ) == 1

    assert Enum.map(events(oracle, "watch_presence", "connect_watcher"), & &1["kind"]) ==
             ["server_info", "peer_present", "peer_present"]
  end

  defp dropped(kind, reason), do: ~s(derp_packets_dropped{kind="#{kind}",reason="#{reason}"})

  defp step(trace, scenario_name, step_name) do
    scenario = Enum.find(trace["scenarios"], &(&1["name"] == scenario_name))
    assert scenario, "no scenario named #{scenario_name}"
    found = Enum.find(scenario["steps"], &(&1["step"] == step_name))
    assert found, "no step named #{step_name} in #{scenario_name}"
    found
  end

  defp counter(trace, scenario_name, step_name, metric) do
    counters = step(trace, scenario_name, step_name)["counters"]
    assert Map.has_key?(counters, metric), "step #{step_name} does not track #{metric}"
    counters[metric]
  end

  defp events(trace, scenario_name, step_name),
    do: step(trace, scenario_name, step_name)["events"]

  defp run_trace!(upstream, helper, arguments) do
    {output, status} =
      System.cmd("go", ["run", helper | arguments],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    encoded =
      output
      |> String.split("\n", trim: true)
      |> Enum.find_value(fn
        "DERPEX_TRACE " <> trace -> trace
        _line -> nil
      end)

    assert encoded, output
    :json.decode(encoded)
  end
end
