# This module implements the directory discovery of golang.org/x/crypto/acme,
# as vendored at ../tailscale/tempfork/acme.
# Copyright (c) 2015 The Go Authors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.Directory do
  @moduledoc """
  The ACME directory: the one unauthenticated GET in the protocol.

  Everything else is addressed by a URL the directory hands out, so nothing
  here hardcodes a path. `meta.profiles` is the RFC 8555 profiles extension;
  a certificate authority that does not advertise the profile an order asks
  for cannot serve it, and upstream refuses the order rather than silently
  taking whatever the default profile issues.
  """

  alias Derpex.ACME.HTTP

  @type t :: %{
          new_nonce: binary(),
          new_account: binary(),
          new_order: binary(),
          terms: binary() | nil,
          profiles: [binary()]
        }

  @doc "Fetches and parses the directory at `url`."
  @spec fetch(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def fetch(url, options \\ []) do
    with {:ok, %{status: 200, body: body}} <- HTTP.get(url, options),
         {:ok, fields} <- decode(body) do
      parse(fields)
    else
      {:ok, %{status: status}} -> {:error, {:directory_status, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Reports whether the directory advertises a certificate profile."
  @spec supports_profile?(t(), binary() | nil) :: boolean()
  def supports_profile?(_directory, nil), do: true
  def supports_profile?(directory, profile), do: profile in directory.profiles

  defp decode(body) do
    case Derpex.JSON.decode_object(body) do
      {:ok, fields} -> {:ok, fields}
      {:error, reason} -> {:error, {:directory_body, reason}}
    end
  end

  defp parse(fields) do
    with {:ok, new_nonce} <- required(fields, "newNonce"),
         {:ok, new_account} <- required(fields, "newAccount"),
         {:ok, new_order} <- required(fields, "newOrder") do
      {:ok,
       %{
         new_nonce: new_nonce,
         new_account: new_account,
         new_order: new_order,
         terms: HTTP.field(meta(fields), "termsOfService"),
         profiles: profiles(fields)
       }}
    end
  end

  defp meta(fields) do
    case HTTP.field(fields, "meta") do
      {:object, meta} -> meta
      _absent -> []
    end
  end

  defp profiles(fields) do
    case HTTP.field(meta(fields), "profiles") do
      {:object, profiles} -> Enum.map(profiles, fn {name, _description} -> name end)
      _absent -> []
    end
  end

  defp required(fields, key) do
    case HTTP.field(fields, key) do
      value when is_binary(value) -> {:ok, value}
      _missing -> {:error, {:directory_missing, key}}
    end
  end
end
