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

    assert [%{cert: [certificate_der], key: _private_key}] =
             Manual.tls_options(loaded)[:certs_keys]

    assert certificate_der == manual.certificate_der
  end
end
