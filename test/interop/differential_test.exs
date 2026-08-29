defmodule Derpex.Interop.DifferentialTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  @moduletag :differential
  @moduletag timeout: 180_000

  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Secret

  @mesh_key_hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  @operations_token "differential-trace-operations-token"

  test "pinned Go server and DERPEX produce the same normalized semantic trace" do
    upstream =
      System.get_env("DERPEX_TAILSCALE_DIR") ||
        raise "DERPEX_TAILSCALE_DIR must name the pinned Tailscale checkout"

    {actual_commit, 0} = System.cmd("git", ["rev-parse", "HEAD"], cd: upstream)
    assert String.trim(actual_commit) == "1e69418c298b680562a2fecd7020f7f58d17d166"

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

    assert derpex == oracle

    # The traces are only worth comparing if the oracle's own run moved the
    # counters the scenarios claim to exercise; identical all-zero traces would
    # otherwise pass trivially.
    assert Enum.map(oracle["scenarios"], & &1["name"]) ==
             ["relay_and_drops", "duplicate_keys", "watch_presence"]

    assert counter(oracle, "relay_and_drops", "relay_payloads", "derp_packets_sent") == 3
    assert counter(oracle, "relay_and_drops", "ping_pong", "derp_got_ping") == 1
    assert counter(oracle, "relay_and_drops", "ping_pong", "derp_sent_pong") == 1

    assert counter(
             oracle,
             "relay_and_drops",
             "unknown_destination",
             ~s(derp_packets_dropped{kind="disco",reason="unknown_dest"})
           ) == 1

    assert counter(
             oracle,
             "relay_and_drops",
             "unknown_destination",
             "derp_peer_gone_not_here_frames"
           ) == 1

    assert counter(
             oracle,
             "relay_and_drops",
             "flood_stalled_recipient",
             ~s(derp_packets_dropped{kind="other",reason="queue_head"})
           ) == 1

    assert counter(oracle, "relay_and_drops", "close_first", "derp_peer_gone_disconnected_frames") ==
             1

    assert counter(
             oracle,
             "duplicate_keys",
             "connect_duplicates",
             "derp_total_dup_client_conns"
           ) == 1

    assert counter(
             oracle,
             "duplicate_keys",
             "connect_duplicates",
             "derp_current_dup_client_keys"
           ) == 1

    assert counter(
             oracle,
             "duplicate_keys",
             "connect_duplicates",
             "derp_current_dup_client_conns"
           ) == 2

    assert counter(
             oracle,
             "watch_presence",
             "close_second_regular",
             "derp_peer_gone_disconnected_frames"
           ) == 1

    assert Enum.map(events(oracle, "watch_presence", "connect_watcher"), & &1["kind"]) ==
             ["server_info", "peer_present", "peer_present"]
  end

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
