# This module implements the JWS encoding of golang.org/x/crypto/acme's jws.go,
# as vendored at ../tailscale/tempfork/acme.
# Copyright (c) 2015 The Go Authors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.JWS do
  @moduledoc """
  JSON Web Signatures for ACME, over P-256 only.

  Every ACME request is a flattened JWS (RFC 7515) whose protected header
  carries either the account key as a JWK, before the account exists, or the
  account URL as `kid` afterwards. RFC 8555 calls a request with an empty
  payload POST-as-GET.

  Two details are load-bearing and easy to get wrong:

  - ES256 signatures are the raw `r || s` pair, each left-padded to the curve
    size. `:public_key.sign/3` produces a DER `ECDSA-Sig-Value`, so it is
    decoded and re-encoded here.
  - The JWK a thumbprint is taken over is canonical JSON with its members in
    lexicographic order and no whitespace (RFC 7638 section 3.3), which is why
    both it and the protected header are built as strings rather than through a
    map, whose member order is not ours to choose.
  """

  alias Derpex.JSON

  @curve {:namedCurve, :secp256r1}
  @coordinate_bytes 32
  @coordinate_bits @coordinate_bytes * 8

  @type account_key :: tuple()
  @type external_account :: %{kid: binary(), key: binary()}
  @type flattened :: %{protected: binary(), payload: binary(), signature: binary()}

  @doc "Generates a P-256 account key."
  @spec generate_account_key() :: account_key()
  def generate_account_key, do: :public_key.generate_key(@curve)

  @doc "Returns the OTP public key for an account key, for signature verification."
  @spec public_key(account_key()) :: {tuple(), tuple()}
  def public_key(key), do: {{:ECPoint, elem(key, 4)}, @curve}

  @doc "Returns the canonical JWK of an account key, as RFC 7638 requires it."
  @spec jwk(account_key()) :: binary()
  def jwk(key) do
    <<4, x::binary-size(@coordinate_bytes), y::binary-size(@coordinate_bytes)>> = elem(key, 4)
    ~s({"crv":"P-256","kty":"EC","x":"#{encode(x)}","y":"#{encode(y)}"})
  end

  @doc "Returns the RFC 7638 thumbprint of an account key."
  @spec thumbprint(account_key()) :: binary()
  def thumbprint(key), do: :sha256 |> :crypto.hash(jwk(key)) |> encode()

  @doc """
  Encodes one flattened JWS request body.

  `payload` is a map to encode, or `:post_as_get` for RFC 8555's authenticated
  GET. Pass `:kid` once the account URL is known; without it the account key is
  inlined as a JWK, which is what `newAccount` requires.
  """
  @spec encode(map() | :post_as_get, account_key(), keyword()) :: binary()
  def encode(payload, key, options) do
    protected =
      key
      |> protected_header(
        Keyword.get(options, :kid),
        Keyword.get(options, :nonce),
        Keyword.fetch!(options, :url)
      )
      |> encode()

    payload = encode_payload(payload)

    JSON.encode_object([
      {"protected", protected},
      {"payload", payload},
      {"signature", sign(protected <> "." <> payload, key)}
    ])
  end

  @doc """
  Returns the external-account-binding inner JWS (RFC 8555 section 7.3.4).

  The payload is the account JWK verbatim and the signature is HMAC-SHA256
  under the key the CA issued out of band. GCP's ACME endpoint requires it.
  """
  @spec external_account_binding(external_account(), account_key(), binary()) :: flattened()
  def external_account_binding(%{kid: kid, key: mac_key}, account_key, url)
      when byte_size(mac_key) > 0 do
    protected =
      ~s({"alg":"HS256","kid":#{string(kid)},"url":#{string(url)}})
      |> encode()

    payload = account_key |> jwk() |> encode()

    signature =
      :hmac
      |> :crypto.mac(:sha256, mac_key, protected <> "." <> payload)
      |> encode()

    %{protected: protected, payload: payload, signature: signature}
  end

  defp protected_header(key, kid, nonce, url) do
    members =
      [~s("alg":"ES256")] ++
        identity(key, kid) ++
        nonce_member(nonce) ++
        [~s("url":#{string(url)})]

    "{" <> Enum.join(members, ",") <> "}"
  end

  defp identity(key, nil), do: [~s("jwk":#{jwk(key)})]
  defp identity(_key, kid), do: [~s("kid":#{string(kid)})]

  defp nonce_member(nil), do: []
  defp nonce_member(nonce), do: [~s("nonce":#{string(nonce)})]

  defp encode_payload(:post_as_get), do: ""

  defp encode_payload(payload) when is_map(payload) do
    payload |> Map.to_list() |> JSON.encode_object() |> encode()
  end

  # ES256 signs over the ASCII signing input, and JWS wants the raw coordinate
  # pair rather than the DER structure OTP returns.
  defp sign(signing_input, key) do
    {:"ECDSA-Sig-Value", r, s} =
      signing_input
      |> :public_key.sign(:sha256, key)
      |> then(&:public_key.der_decode(:"ECDSA-Sig-Value", &1))

    encode(<<r::unsigned-big-size(@coordinate_bits), s::unsigned-big-size(@coordinate_bits)>>)
  end

  defp string(text), do: text |> :json.encode_binary() |> IO.iodata_to_binary()

  defp encode(binary), do: Base.url_encode64(binary, padding: false)
end
