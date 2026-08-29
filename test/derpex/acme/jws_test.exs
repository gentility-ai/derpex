defmodule Derpex.ACME.JWSTest do
  use ExUnit.Case, async: true

  alias Derpex.ACME.JWS
  alias Derpex.JSON

  test "encodes an ES256 JWS whose signature verifies as raw r||s" do
    key = JWS.generate_account_key()

    encoded =
      JWS.encode(%{"termsOfServiceAgreed" => true}, key,
        nonce: "test-nonce",
        url: "https://ca.example/new-account"
      )

    assert {:ok, fields} = JSON.decode_object(encoded)
    protected = Keyword.fetch!(atomize(fields), :protected)
    payload = Keyword.fetch!(atomize(fields), :payload)
    signature = Keyword.fetch!(atomize(fields), :signature)

    assert {:ok, header} = protected |> url_decode() |> JSON.decode_object()
    header = atomize(header)
    assert Keyword.fetch!(header, :alg) == "ES256"
    assert Keyword.fetch!(header, :nonce) == "test-nonce"
    assert Keyword.fetch!(header, :url) == "https://ca.example/new-account"
    refute Keyword.has_key?(header, :kid)
    assert {:object, jwk} = Keyword.fetch!(header, :jwk)
    assert atomize(jwk)[:kty] == "EC"
    assert atomize(jwk)[:crv] == "P-256"

    assert {:ok, [{"termsOfServiceAgreed", true}]} =
             payload |> url_decode() |> JSON.decode_object()

    # RFC 7515 ES256 is the raw pair, not the DER structure OTP signs with.
    raw = url_decode(signature)
    assert byte_size(raw) == 64
    <<r::unsigned-big-256, s::unsigned-big-256>> = raw
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})

    assert :public_key.verify(
             protected <> "." <> payload,
             :sha256,
             der,
             JWS.public_key(key)
           )
  end

  test "uses a key identifier instead of a JWK once an account exists" do
    key = JWS.generate_account_key()

    encoded =
      JWS.encode(:post_as_get, key,
        kid: "https://ca.example/account/1",
        nonce: "n",
        url: "https://ca.example/order/1"
      )

    assert {:ok, fields} = JSON.decode_object(encoded)
    fields = atomize(fields)
    assert Keyword.fetch!(fields, :payload) == ""

    assert {:ok, header} =
             fields |> Keyword.fetch!(:protected) |> url_decode() |> JSON.decode_object()

    header = atomize(header)
    assert Keyword.fetch!(header, :kid) == "https://ca.example/account/1"
    refute Keyword.has_key?(header, :jwk)
  end

  test "produces the RFC 7638 thumbprint over the canonical JWK" do
    key = JWS.generate_account_key()
    jwk = JWS.jwk(key)

    # Field order is normative for a thumbprint: crv, kty, x, y.
    assert jwk =~ ~r/^\{"crv":"P-256","kty":"EC","x":"[^"]+","y":"[^"]+"\}$/
    assert JWS.thumbprint(key) == Base.url_encode64(:crypto.hash(:sha256, jwk), padding: false)

    # Coordinates are left-padded to the curve size, never trimmed.
    assert {:object, fields} = decode_value(jwk)
    fields = atomize(fields)
    assert byte_size(url_decode(Keyword.fetch!(fields, :x))) == 32
    assert byte_size(url_decode(Keyword.fetch!(fields, :y))) == 32
  end

  test "binds an external account with an HS256 inner JWS over the account JWK" do
    key = JWS.generate_account_key()
    mac_key = :crypto.strong_rand_bytes(32)
    url = "https://dv.acme-v02.api.pki.goog/new-account"

    binding = JWS.external_account_binding(%{kid: "eab-kid", key: mac_key}, key, url)

    assert {:ok, header} = binding.protected |> url_decode() |> JSON.decode_object()
    header = atomize(header)
    assert Keyword.fetch!(header, :alg) == "HS256"
    assert Keyword.fetch!(header, :kid) == "eab-kid"
    assert Keyword.fetch!(header, :url) == url

    # The payload is the account JWK verbatim, and the MAC covers the two
    # base64url segments joined by a period.
    assert url_decode(binding.payload) == JWS.jwk(key)

    expected =
      :hmac
      |> :crypto.mac(:sha256, mac_key, binding.protected <> "." <> binding.payload)
      |> Base.url_encode64(padding: false)

    assert binding.signature == expected
  end

  defp atomize(fields), do: Enum.map(fields, fn {key, value} -> {String.to_atom(key), value} end)

  defp url_decode(text), do: Base.url_decode64!(text, padding: false)

  defp decode_value(text) do
    {:ok, fields} = JSON.decode_object(text)
    {:object, fields}
  end
end
