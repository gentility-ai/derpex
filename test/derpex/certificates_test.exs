defmodule Derpex.CertificatesTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates
  alias Derpex.MetaCertificate

  test "concurrent metacertificate augmentation never mutates or grows a provider chain" do
    server_public_key = :crypto.strong_rand_bytes(32)
    provider_chain = [<<1, 2, 3>>]
    expected_meta = MetaCertificate.generate(server_public_key)

    results =
      1..100
      |> Task.async_stream(fn _iteration ->
        Certificates.append_meta_certificate(provider_chain, expected_meta)
      end)
      |> Enum.map(fn {:ok, chain} -> chain end)

    assert Enum.all?(results, &(&1 == [<<1, 2, 3>>, expected_meta]))
    assert provider_chain == [<<1, 2, 3>>]
  end

  test "loads a matching PKCS8 ECDSA certificate and private key" do
    openssl = System.find_executable("openssl") || flunk("openssl is required for this test")
    directory = Path.join(System.tmp_dir!(), "derpex-ecdsa-#{System.unique_integer([:positive])}")
    certificate_path = Path.join(directory, "certificate.pem")
    key_path = Path.join(directory, "private-key.pem")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)

    {output, status} =
      System.cmd(
        openssl,
        [
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-nodes",
          "-keyout",
          key_path,
          "-out",
          certificate_path,
          "-days",
          "1",
          "-subj",
          "/CN=localhost"
        ],
        stderr_to_stdout: true
      )

    assert status == 0, output

    assert [certs_keys: [%{cert: [_leaf, _meta], key: {:PrivateKeyInfo, key_der}}]] =
             Certificates.transport_options(
               certificate_path,
               key_path,
               :crypto.strong_rand_bytes(32)
             )

    assert is_binary(key_der)
  end
end
