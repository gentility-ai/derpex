defmodule Derpex.ListenerSupervisorTest do
  # Publishing a listener snapshot marks a bootstrap subject that the
  # readiness probe and the certificate gauge read globally, so these run
  # alone rather than beside a test that asserts readiness.
  use ExUnit.Case, async: false

  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Manual
  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Secret

  test "derives the server public key once per listener into its handler options" do
    {server_public, server_private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 1, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    handler_options = Keyword.fetch!(options, :handler_options)

    assert Keyword.fetch!(handler_options, :server_public_key) == server_public
  end

  test "binds the IP certificate manager's certificate to a self-issuer TLS listener" do
    {server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-listener-ipcert-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    manager =
      start_supervised!(
        {IPManager, directory: directory, issuer: &IPManager.self_signed_issuer/2}
      )

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [ip: {127, 0, 0, 1}, versions: [:"tlsv1.3"]],
      ip_certificate_manager: {manager, "127.0.0.1"}
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    refute Keyword.has_key?(options, :ip_certificate_manager)
    transport_options = Keyword.fetch!(options, :transport_options)

    # Nothing is ordered while the listeners are still being built, so the
    # socket binds a self-signed placeholder for the same address.
    assert [%{cert: [placeholder, meta_certificate], key: {_type, _der}}] =
             Keyword.fetch!(transport_options, :certs_keys)

    assert :ok = Manual.verify_certificate(placeholder, "127.0.0.1")
    assert IPManager.bootstrap_certificate_active?()

    assert common_name(meta_certificate) ==
             "derpkey" <> Base.encode16(server_public, case: :lower)

    # Once the listeners are accepting, the manager issues and publishes into
    # the listener snapshot, and the placeholder state clears.
    :ok = IPManager.ensure(manager, "127.0.0.1")
    assert {:ok, leaf} = await_issued(manager)
    refute leaf == placeholder
    refute IPManager.bootstrap_certificate_active?()

    # One metacertificate per listener, shared by the bound options and every
    # SNI answer: it only carries the node key, and an RSA key pair per hello
    # would cost more than the DERP handshake it advertises.
    sni_fun = Keyword.fetch!(transport_options, :sni_fun)
    assert [certs_keys: [%{cert: [^leaf, ^meta_certificate]}]] = sni_fun.(~c"127.0.0.1")

    # OTP reads `:undefined` as "use the listen options", which would serve the
    # listener's certificate to a name this manager just refused. A refusal has
    # to be `:unrecognized`, which sends an unrecognized_name alert.
    assert sni_fun.(~c"203.0.113.9") == :unrecognized
    assert sni_fun.(~c"derp.example.com") == :unrecognized
  end

  test "a mismatched SNI reaches the client as an unrecognized_name alert" do
    {_server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-listener-sni-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    manager =
      start_supervised!(
        Supervisor.child_spec(
          {IPManager, directory: directory, issuer: &IPManager.self_signed_issuer/2},
          id: :sni_manager
        )
      )

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [ip: {127, 0, 0, 1}, versions: [:"tlsv1.3"]],
      ip_certificate_manager: {manager, "127.0.0.1"}
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    server = start_supervised!({ThousandIsland, options}, id: :sni_listener)
    assert {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    for name <- [~c"203.0.113.9", ~c"derp.example.com"] do
      assert {:error, {:tls_alert, {:unrecognized_name, _description}}} =
               :ssl.connect(
                 ~c"127.0.0.1",
                 port,
                 [verify: :verify_none, server_name_indication: name, active: false],
                 5_000
               ),
             "SNI #{name} was not refused"
    end
  end

  # A self-signed placeholder is a single certificate with no path to build, so
  # an OTP client refuses it however the chain is verified. What this asserts is
  # that OTP accepts the certificate and key when the listen socket is opened;
  # a handshake against a chain an authority signed is asserted end to end in
  # test/derpex/certificates/acme_boot_test.exs.
  test "OTP opens a listen socket with the self-issued certificate and key" do
    {_server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-listener-tls-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    manager =
      start_supervised!(
        Supervisor.child_spec(
          {IPManager, directory: directory, issuer: &IPManager.self_signed_issuer/2},
          id: :tls_manager
        )
      )

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [ip: {127, 0, 0, 1}, versions: [:"tlsv1.3"]],
      ip_certificate_manager: {manager, "127.0.0.1"}
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    server = start_supervised!({ThousandIsland, options}, id: :tls_listener)
    assert {:ok, {{127, 0, 0, 1}, port}} = ThousandIsland.listener_info(server)
    assert port > 0
    assert {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [active: false], 5_000)
    on_exit(fn -> :gen_tcp.close(socket) end)
  end

  test "leaves a listener alone when no IP certificate issuer is configured" do
    {_server_public, server_private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 1, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    refute Keyword.has_key?(Keyword.fetch!(options, :transport_options), :certs_keys)
  end

  test "a configured socket write timeout reaches the handler that must respect it" do
    {_server_public, server_private} = Crypto.generate_keypair()

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_options: [ip: {127, 0, 0, 1}],
      socket_options: [write_timeout_ms: 10_000]
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    handler_options = Keyword.fetch!(options, :handler_options)
    transport_options = Keyword.fetch!(options, :transport_options)

    # The handler's control writes and the socket itself follow the same
    # deadline; a control write that gave up first would abandon a write the
    # socket was still allowed to be making.
    assert Keyword.fetch!(handler_options, :write_timeout_ms) == 10_000
    assert Keyword.fetch!(transport_options, :send_timeout) == 10_000
  end

  test "a listener caps its concurrent connections and its idle reads" do
    {_server_public, server_private} = Crypto.generate_keypair()

    listener = [
      port: 0,
      num_acceptors: 8,
      transport_options: [ip: {127, 0, 0, 1}]
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start

    # Thousand Island counts connections per acceptor, so the cap has to be
    # divided by the acceptors that share it.
    assert Keyword.fetch!(options, :num_connections) * 8 <= 65_536
    assert Keyword.fetch!(options, :read_timeout) == 60_000
  end

  test "a configured connection cap and read timeout are the ones used" do
    {_server_public, server_private} = Crypto.generate_keypair()
    previous_max = Application.get_env(:derpex, :max_connections)
    previous_timeout = Application.get_env(:derpex, :read_timeout_ms)
    Application.put_env(:derpex, :max_connections, 1_024)
    Application.put_env(:derpex, :read_timeout_ms, 15_000)

    on_exit(fn ->
      restore(:max_connections, previous_max)
      restore(:read_timeout_ms, previous_timeout)
    end)

    listener = [port: 0, num_acceptors: 4, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    assert Keyword.fetch!(options, :num_connections) == 256
    assert Keyword.fetch!(options, :read_timeout) == 15_000
  end

  defp restore(key, nil), do: Application.delete_env(:derpex, key)
  defp restore(key, value), do: Application.put_env(:derpex, key, value)

  test "an unconfigured listener hands the handler the pinned default" do
    {_server_public, server_private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 1, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start

    assert Keyword.fetch!(Keyword.fetch!(options, :handler_options), :write_timeout_ms) ==
             Derpex.SocketOptions.default_write_timeout_ms()
  end

  defp await_issued(manager, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 5_000

    case IPManager.certificate(manager, "127.0.0.1") do
      {:ok, %{certificate_der: der}} ->
        {:ok, der}

      {:error, reason} ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("no certificate was issued: #{inspect(reason)}")
        else
          Process.sleep(10)
          await_issued(manager, deadline)
        end
    end
  end

  defp common_name(certificate_der) do
    {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, common_name}}]]} =
      certificate_der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(6)

    IO.chardata_to_string(common_name)
  end
end
