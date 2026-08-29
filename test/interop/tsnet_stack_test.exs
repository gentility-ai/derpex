defmodule Derpex.Interop.TsnetStackTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  @moduletag timeout: 120_000

  alias Derpex.Certificates.Manual
  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor

  test "official tsnet nodes relay an encrypted tunnel ping through DERPEX" do
    upstream =
      System.get_env("DERPEX_TAILSCALE_DIR") ||
        raise "DERPEX_TAILSCALE_DIR must name the pinned Tailscale checkout"

    {actual_commit, 0} = System.cmd("git", ["rev-parse", "HEAD"], cd: upstream)
    assert String.trim(actual_commit) == "1e69418c298b680562a2fecd7020f7f58d17d166"

    {_server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-tsnet-tls-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")

    listener = [
      port: 0,
      transport_module: ThousandIsland.Transports.SSL,
      certificate_reload_interval_ms: 60_000,
      transport_options: [
        certfile: manual.certificate_path,
        keyfile: manual.key_path,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        alpn_preferred_protocols: ["http/1.1"],
        send_timeout: 2_000,
        send_timeout_close: true
      ]
    ]

    # Runs through ListenerSupervisor so the tsnet gate exercises the
    # certificate reloader's paused-handshake path.
    server =
      start_supervised!({ListenerSupervisor, {[listener], server_private}})
      |> Supervisor.which_children()
      |> Enum.find_value(fn
        {{ThousandIsland, _index}, pid, _type, _modules} -> pid
        _other -> nil
      end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/tsnet_stack_smoke_test.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["test", "-count=1", "-run", "^TestDERPEXTsnetStack$", "-timeout", "90s", "-v", helper],
        cd: upstream,
        stderr_to_stdout: true,
        env: [
          {"DERPEX_INTEROP_PORT", Integer.to_string(port)},
          {"DERPEX_INTEROP_CERT_PIN", Manual.raw_pin(manual)},
          {"GOTOOLCHAIN", "local"},
          {"TS_DEBUG_NEVER_DIRECT_UDP", "1"}
        ]
      )

    assert status == 0, output

    assert output =~
             "official tsnet nodes relayed an encrypted tunnel ping through DERPEX"
  end
end
