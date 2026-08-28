defmodule Derpex.Interop.GoClientTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop

  alias Derpex.Crypto
  alias Derpex.Certificates
  alias Derpex.Listener.Handler

  test "unchanged official derphttp.Client authenticates to DERPEX" do
    upstream =
      System.get_env("DERPEX_TAILSCALE_DIR") ||
        raise "DERPEX_TAILSCALE_DIR must name the pinned Tailscale checkout"

    {expected_commit, 0} = System.cmd("git", ["-C", upstream, "rev-parse", "HEAD"])
    assert String.trim(expected_commit) == "1e69418c298b680562a2fecd7020f7f58d17d166"

    {_server_public, server_private} = Crypto.generate_keypair()
    parent = self()

    event_handler = fn event ->
      send(parent, event)
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private, event_handler: event_handler]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/client_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go client authenticated and pinged"
    assert_receive {:authenticated, _client_public_key, %Derpex.ClientInfo{version: 2}}, 2_000
  end

  test "two unchanged official Go clients relay packet boundaries and peer-gone through DERPEX" do
    upstream = System.fetch_env!("DERPEX_TAILSCALE_DIR")
    {_server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/relay_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    assert output =~
             "official Go clients relayed packet boundaries and observed both peer-gone reasons"
  end

  test "duplicate official Go clients use last-writer-active routing" do
    upstream = System.fetch_env!("DERPEX_TAILSCALE_DIR")
    {_server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/duplicate_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go clients observed last-writer-active duplicate routing"
  end

  test "official Go client uses TLS 1.3 metacertificate fast start" do
    upstream = System.fetch_env!("DERPEX_TAILSCALE_DIR")
    {server_public, server_private} = Crypto.generate_keypair()
    directory = Path.join(System.tmp_dir!(), "derpex-tls-#{System.unique_integer([:positive])}")
    certificate = Path.join(directory, "certificate.pem")
    private_key = Path.join(directory, "private-key.pem")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)

    {openssl_output, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-nodes",
          "-keyout",
          private_key,
          "-out",
          certificate,
          "-days",
          "1",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=DNS:localhost"
        ],
        stderr_to_stdout: true
      )

    assert is_binary(openssl_output)

    transport_options =
      Certificates.transport_options(certificate, private_key, server_public) ++
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
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/tls_smoke.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["run", helper, "https://localhost:#{port}/derp", certificate],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go client used TLS 1.3 metacertificate fast start"
  end
end
