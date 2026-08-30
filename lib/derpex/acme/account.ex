# This module implements the account registration of golang.org/x/crypto/acme,
# as vendored at ../tailscale/tempfork/acme, and the account key file
# cmd/derper's ipcert.go keeps beside its certificates.
# Copyright (c) 2015 The Go Authors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.Account do
  @moduledoc """
  The ACME account: a persistent key, and the `newAccount` request over it.

  The account key identifies the relay to the certificate authority for the
  life of the deployment, so it is created once and kept at `0600` beside the
  certificates, exactly where upstream's `loadOrCreateAccountKey` keeps it.

  Registration is idempotent: a `200` means the key already has an account and
  a `201` means one was created, and both carry the account URL in `Location`,
  which becomes the `kid` of every later request.
  """

  alias Derpex.ACME.HTTP
  alias Derpex.ACME.JWS
  alias Derpex.AtomicFile

  @key_mode 0o600
  @account_key_file "acme-account.key"

  @doc "Returns the account key at `directory`, creating one on first use."
  @spec load_or_create_key(Path.t()) :: {:ok, JWS.account_key()} | {:error, term()}
  def load_or_create_key(directory) do
    path = Path.join(directory, @account_key_file)

    case File.read(path) do
      {:ok, pem} -> decode_key(pem, path)
      {:error, :enoent} -> create_key(path)
      {:error, reason} -> {:error, {:account_key_read, reason}}
    end
  end

  @doc "Returns the `newAccount` payload, with an external account binding when configured."
  @spec payload(keyword(), JWS.account_key(), binary()) :: map()
  def payload(options, account_key, new_account_url) do
    %{"termsOfServiceAgreed" => true}
    |> contact(Keyword.get(options, :email))
    |> binding(Keyword.get(options, :external_account), account_key, new_account_url)
  end

  @doc """
  Reads the account URL out of a `newAccount` response.

  Both `201 Created` and `200 OK` are success: the second means this key was
  already registered, which upstream treats as `ErrAccountAlreadyExists` and
  then keeps using the URL anyway.
  """
  @spec identifier(HTTP.response()) :: {:ok, binary()} | {:error, term()}
  def identifier(%{status: status} = response) when status in [200, 201] do
    case HTTP.header(response, "location") do
      url when is_binary(url) and url != "" -> {:ok, url}
      _missing -> {:error, :account_without_location}
    end
  end

  def identifier(response), do: {:error, {:account_status, response.status}}

  defp contact(payload, nil), do: payload
  defp contact(payload, ""), do: payload
  defp contact(payload, email), do: Map.put(payload, "contact", ["mailto:" <> email])

  defp binding(payload, nil, _account_key, _url), do: payload

  defp binding(payload, external_account, account_key, url) do
    jws = JWS.external_account_binding(external_account, account_key, url)

    Map.put(payload, "externalAccountBinding", %{
      "protected" => jws.protected,
      "payload" => jws.payload,
      "signature" => jws.signature
    })
  end

  defp decode_key(pem, path) do
    case :public_key.pem_decode(pem) do
      [{:ECPrivateKey, _der, :not_encrypted} = entry | _rest] ->
        {:ok, :public_key.pem_entry_decode(entry)}

      _invalid ->
        {:error, {:invalid_account_key, path}}
    end
  rescue
    _error -> {:error, {:invalid_account_key, path}}
  end

  defp create_key(path) do
    key = JWS.generate_account_key()

    pem =
      :ECPrivateKey
      |> :public_key.pem_entry_encode(key)
      |> List.wrap()
      |> :public_key.pem_encode()

    case AtomicFile.write(path, pem, mode: @key_mode) do
      :ok -> {:ok, key}
      {:error, reason} -> {:error, {:account_key_write, reason}}
    end
  end
end
