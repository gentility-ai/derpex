defmodule Derpex.Interop.DifferentialTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  @moduletag :differential
  @moduletag timeout: 120_000

  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Secret

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
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public
        ]
      )

    on_exit(fn -> if Process.alive?(server), do: Process.exit(server, :shutdown) end)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/differential_trace.go", __DIR__)

    oracle = run_trace!(upstream, helper, "oracle")
    derpex = run_trace!(upstream, helper, "http://127.0.0.1:#{port}/derp")

    assert derpex == oracle
    assert length(oracle["relayed_packets"]) == 3
    assert Enum.map(oracle["peer_gone"], & &1["reason"]) == [0, 1]

    assert oracle["duplicate_routing"] == [
             "newest_connection",
             "older_wrote",
             "last_writer_receives"
           ]
  end

  defp run_trace!(upstream, helper, target) do
    {output, status} =
      System.cmd("go", ["run", helper, target],
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
