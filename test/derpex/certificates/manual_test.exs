defmodule Derpex.Certificates.ManualTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates.Manual

  test "creates, validates, and reuses a self-signed bare-IP certificate" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-manual-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    assert {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")
    assert File.exists?(manual.certificate_path)
    assert File.exists?(manual.key_path)
    assert String.starts_with?(Manual.raw_pin(manual), "sha256-raw:")
    assert byte_size(Manual.raw_pin(manual)) == byte_size("sha256-raw:") + 64

    certificate = :public_key.pkix_decode_cert(manual.certificate_der, :otp)
    assert :public_key.pkix_verify_hostname(certificate, ip: {127, 0, 0, 1})

    assert {:ok, loaded} = Manual.load_or_create(directory, "127.0.0.1")
    assert loaded.certificate_der == manual.certificate_der
    assert Manual.raw_pin(loaded) == Manual.raw_pin(manual)

    assert [%{cert: [certificate_der], key: {key_type, key_der}}] =
             Manual.tls_options(loaded)[:certs_keys]

    assert certificate_der == manual.certificate_der
    assert is_atom(key_type)
    assert is_binary(key_der)

    tls_options =
      Manual.tls_options(loaded) ++
        [ip: {127, 0, 0, 1}, active: false, versions: [:"tlsv1.3"]]

    assert {:ok, listener} = :ssl.listen(0, tls_options)
    assert :ok = :ssl.close(listener)
  end

  test "writes the generated key pair through the atomic private-file path" do
    directory =
      Path.join([
        System.tmp_dir!(),
        "derpex-manual-modes-#{System.unique_integer([:positive])}",
        "nested"
      ])

    on_exit(fn -> File.rm_rf!(Path.dirname(directory)) end)

    assert {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")

    assert file_mode(manual.key_path) == 0o600
    assert file_mode(manual.certificate_path) == 0o644
    assert file_mode(directory) == 0o700
    assert Enum.filter(File.ls!(directory), &String.contains?(&1, ".tmp.")) == []
  end

  defp file_mode(path) do
    {:ok, stat} = File.stat(path)
    Bitwise.band(stat.mode, 0o777)
  end
end
