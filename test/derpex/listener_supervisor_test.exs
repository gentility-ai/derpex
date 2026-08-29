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

    sni_fun = Keyword.fetch!(transport_options, :sni_fun)
    assert [certs_keys: [%{cert: [^leaf, sni_meta_certificate]}]] = sni_fun.(~c"127.0.0.1")

    assert common_name(sni_meta_certificate) ==
             "derpkey" <> Base.encode16(server_public, case: :lower)

    assert sni_fun.(~c"203.0.113.9") == :undefined
    assert sni_fun.(~c"derp.example.com") == :undefined
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
