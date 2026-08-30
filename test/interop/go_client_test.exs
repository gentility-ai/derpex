defmodule Derpex.Interop.GoClientTest do
  use ExUnit.Case, async: false

  @moduletag :go_interop
  # Every test here shells out to `go run`, and the prober scenario moves 100 MB
  # through the relay. On a cold Go build cache the default sixty seconds is a
  # timeout on the toolchain rather than on DERPEX.
  @moduletag timeout: 300_000

  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.ListenerSupervisor
  alias Derpex.Secret
  alias Derpex.ServerInfo
  alias Derpex.STUN
  alias Derpex.Test.UpstreamPin

  test "unchanged official derphttp.Client authenticates to DERPEX" do
    upstream = UpstreamPin.checkout!()

    {server_public, server_private} = Crypto.generate_keypair()
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
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler
        ]
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
    upstream = UpstreamPin.checkout!()
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

  test "unchanged official Go client obeys advertised send rate limits" do
    upstream = UpstreamPin.checkout!()
    {server_public, server_private} = Crypto.generate_keypair()

    server_info = %ServerInfo{
      version: 2,
      token_bucket_bytes_per_second: 1,
      token_bucket_bytes_burst: 2 * (5 + 32 + 1_000)
    }

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          server_info: server_info
        ]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/send_rate_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go client obeyed DERPEX send limit"
  end

  test "official DERP prober relays its bounded 100 MB transfer" do
    upstream = UpstreamPin.checkout!()
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

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/prober_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    summary_pattern =
      ~r/^official DERP prober relayed (\d+) bytes through DERPEX \(packets=(\d+) lost=(\d+) reordered=(\d+) corrupted=(\d+)\)$/m

    captures = Regex.run(summary_pattern, output)
    assert captures, output

    [summary, relayed_bytes, packets, lost, reordered, corrupted] = captures

    [relayed_bytes, packets, lost, reordered, corrupted] =
      Enum.map([relayed_bytes, packets, lost, reordered, corrupted], &String.to_integer/1)

    assert reordered == 0, summary
    assert corrupted == 0, summary
    assert lost <= 30, summary
    assert packets + lost == 1_526, summary
    assert relayed_bytes >= 100_000_000 - lost * 65_536, summary
  end

  test "duplicate official Go clients use last-writer-active routing" do
    upstream = UpstreamPin.checkout!()
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
    upstream = UpstreamPin.checkout!()
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

    server = start_tls_listener(certificate, private_key, server_private)

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

  test "official Go region client accepts a raw-IP certificate pin" do
    upstream = UpstreamPin.checkout!()
    {server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-pinned-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")

    server = start_tls_listener(manual.certificate_path, manual.key_path, server_private)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/pinned_cert_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, Integer.to_string(port), Manual.raw_pin(manual)],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go region client accepted DERPEX raw-IP certificate pin"
  end

  test "official low-level client covers unknown and oversize frame edges" do
    upstream = UpstreamPin.checkout!()
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

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/protocol_edges.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "http://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    assert output =~
             "official low-level client discarded a 2-MiB unknown frame and rejected an oversize packet header"

    assert output =~ "server info preceded a packet flood aimed at a connecting key"
  end

  test "unchanged official WebSocket client authenticates and pings" do
    upstream = UpstreamPin.checkout!()
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

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/client_smoke.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["run", "-tags", "ts_debug_websockets", helper, "ws://127.0.0.1:#{port}/derp"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}, {"TS_DEBUG_DERP_WS_CLIENT", "1"}]
      )

    assert status == 0, output
    assert output =~ "official Go client authenticated and pinged"

    relay_helper = Path.expand("../../interop/go/relay_smoke.go", __DIR__)

    {relay_output, relay_status} =
      System.cmd(
        "go",
        [
          "run",
          "-tags",
          "ts_debug_websockets",
          relay_helper,
          "ws://127.0.0.1:#{port}/derp"
        ],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}, {"TS_DEBUG_DERP_WS_CLIENT", "1"}]
      )

    assert relay_status == 0, relay_output

    assert relay_output =~
             "official Go clients relayed packet boundaries and observed both peer-gone reasons"
  end

  test "official STUN client observes its XOR-mapped UDP address" do
    upstream = UpstreamPin.checkout!()
    server = start_supervised!({STUN, ip: {127, 0, 0, 1}, port: 0})
    {:ok, {{127, 0, 0, 1}, port}} = STUN.local_address(server)
    helper = Path.expand("../../interop/go/stun_smoke.go", __DIR__)

    {output, status} =
      System.cmd("go", ["run", helper, "127.0.0.1:#{port}"],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output
    assert output =~ "official Go STUN client observed its XOR-mapped UDP address"
  end

  test "official mesh watcher observes snapshots and live presence" do
    upstream = UpstreamPin.checkout!()
    {server_public, server_private} = Crypto.generate_keypair()
    mesh_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    mesh_key = Base.decode16!(mesh_key_hex, case: :mixed)

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(mesh_key)
        ]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/watch_smoke.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["run", helper, "http://127.0.0.1:#{port}/derp", mesh_key_hex],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    assert output =~
             "official Go mesh watcher observed snapshot, app names, flags, and disconnects"

    assert output =~ "official Go mesh watchers each saw all 100 clients"
  end

  test "official mesh client forwards asserted sources and closes duplicate peers" do
    upstream = UpstreamPin.checkout!()
    {server_public, server_private} = Crypto.generate_keypair()
    mesh_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    mesh_key = Base.decode16!(mesh_key_hex, case: :mixed)

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(mesh_key)
        ]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/mesh_control_smoke.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["run", helper, "http://127.0.0.1:#{port}/derp", mesh_key_hex],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    assert output =~
             "official Go mesh client forwarded asserted sources and closed every duplicate peer"
  end

  test "official clients observe app-name admission and mesh bypass" do
    upstream = UpstreamPin.checkout!()
    {server_public, server_private} = Crypto.generate_keypair()
    mesh_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    mesh_key = Base.decode16!(mesh_key_hex, case: :mixed)

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(mesh_key),
          disallowed_app_names: ["badapp", "worseapp"]
        ]
      )

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)

    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    helper = Path.expand("../../interop/go/admission_smoke.go", __DIR__)

    {output, status} =
      System.cmd(
        "go",
        ["run", helper, "http://127.0.0.1:#{port}/derp", mesh_key_hex],
        cd: upstream,
        stderr_to_stdout: true,
        env: [{"GOTOOLCHAIN", "local"}]
      )

    assert status == 0, output

    assert output =~
             "official Go clients observed disallowed app rejection and trusted mesh bypass"
  end

  defp start_tls_listener(certificate_path, key_path, server_private) do
    listener = [
      port: 0,
      transport_module: ThousandIsland.Transports.SSL,
      certificate_reload_interval_ms: 60_000,
      num_acceptors: 1,
      transport_options: [
        certfile: certificate_path,
        keyfile: key_path,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        alpn_preferred_protocols: ["http/1.1"],
        send_timeout: 2_000,
        send_timeout_close: true
      ]
    ]

    start_supervised!({ListenerSupervisor, {[listener], Secret.wrap(server_private)}})
    |> Supervisor.which_children()
    |> Enum.find_value(fn
      {{ThousandIsland, _index}, pid, _type, _modules} -> pid
      _other -> nil
    end)
  end
end
