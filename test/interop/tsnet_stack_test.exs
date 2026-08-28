defmodule Derpex.Interop.TsnetStackTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  @moduletag timeout: 120_000

  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Crypto
  alias Derpex.Listener.Handler

  test "official tsnet nodes relay an encrypted tunnel ping through DERPEX" do
    upstream =
      System.get_env("DERPEX_TAILSCALE_DIR") ||
        raise "DERPEX_TAILSCALE_DIR must name the pinned Tailscale checkout"

    {actual_commit, 0} = System.cmd("git", ["rev-parse", "HEAD"], cd: upstream)
    assert String.trim(actual_commit) == "1e69418c298b680562a2fecd7020f7f58d17d166"

    {server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-tsnet-tls-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")

    transport_options =
      Certificates.transport_options(
        manual.certificate_path,
        manual.key_path,
        server_public
      ) ++
        [
          ip: {127, 0, 0, 1},
          versions: [:"tlsv1.3"],
          alpn_preferred_protocols: ["http/1.1"],
          send_timeout: 2_000,
          send_timeout_close: true
        ]

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_module: ThousandIsland.Transports.SSL,
        transport_options: transport_options,
        handler_module: Handler,
        handler_options: [server_private_key: server_private]
      )

    on_exit(fn -> if Process.alive?(server), do: Process.exit(server, :shutdown) end)
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
