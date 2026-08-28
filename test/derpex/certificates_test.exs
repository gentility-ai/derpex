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
end
