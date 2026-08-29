defmodule Derpex.ListenerSupervisorTest do
  use ExUnit.Case, async: true

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

    assert [%{cert: [leaf, meta_certificate], key: {_type, _der}}] =
             Keyword.fetch!(transport_options, :certs_keys)

    assert :ok = Manual.verify_certificate(leaf, "127.0.0.1")

    assert common_name(meta_certificate) ==
             "derpkey" <> Base.encode16(server_public, case: :lower)

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

  # The chain DERPEX serves is `[leaf, metacertificate]`, which is upstream's
  # TLS fast-start design rather than a real certificate path, so an OTP client
  # refuses it and the end-to-end handshake belongs to the Go interoperability
  # gate. What this asserts is that OTP accepts the certificate and key the
  # manager issued when the listen socket is opened.
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

  defp common_name(certificate_der) do
    {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, common_name}}]]} =
      certificate_der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(6)

    IO.chardata_to_string(common_name)
  end
end
