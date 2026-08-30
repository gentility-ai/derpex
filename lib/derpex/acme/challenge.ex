# This module implements the http-01 challenge handling of
# golang.org/x/crypto/acme, as vendored at ../tailscale/tempfork/acme.
# Copyright (c) 2015 The Go Authors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.Challenge do
  @moduledoc """
  The HTTP-01 challenge: the only one DERPEX answers.

  The certificate authority connects to port 80 at the address being validated
  and reads `token.thumbprint` from a well-known path. That is exactly the
  reachability a DERP relay already has, and it needs no DNS control, which is
  why upstream uses it for IP address certificates.

  DNS-01 and TLS-ALPN-01 are deliberately absent: DNS-01 cannot validate an IP
  address at all, and TLS-ALPN-01 would need the relay's own TLS listener to
  serve a challenge certificate mid-handshake.
  """

  alias Derpex.ACME.HTTP
  alias Derpex.ACME.JWS

  @type t :: %{url: binary(), token: binary(), status: binary()}

  @prefix "/.well-known/acme-challenge/"
  @type_http_01 "http-01"

  @doc "Returns the path the certificate authority fetches for `token`."
  @spec path(binary()) :: binary()
  def path(token), do: @prefix <> token

  @doc "Returns the key authorization served at that path."
  @spec key_authorization(binary(), JWS.account_key()) :: binary()
  def key_authorization(token, account_key), do: token <> "." <> JWS.thumbprint(account_key)

  @doc "Parses an authorization response, selecting its HTTP-01 challenge."
  @spec select(HTTP.response()) :: {:ok, binary(), t() | nil} | {:error, term()}
  def select(response) do
    with {:ok, fields} <- HTTP.decode(response) do
      status = HTTP.field(fields, "status") || "unknown"

      case {status, http_01(HTTP.field(fields, "challenges"))} do
        {"valid", _challenge} -> {:ok, status, nil}
        {"pending", nil} -> {:error, :no_http_01_challenge}
        {"pending", challenge} -> {:ok, status, challenge}
        {"invalid", _challenge} -> {:error, :authorization_invalid}
        {other, _challenge} -> {:error, {:authorization_status, other}}
      end
    end
  end

  @doc "Returns the status of a challenge or authorization response."
  @spec status(HTTP.response()) :: {:ok, binary()} | {:error, term()}
  def status(response) do
    with {:ok, fields} <- HTTP.decode(response) do
      {:ok, HTTP.field(fields, "status") || "unknown"}
    end
  end

  defp http_01(challenges) when is_list(challenges) do
    Enum.find_value(challenges, fn
      {:object, fields} -> matching(fields)
      _other -> nil
    end)
  end

  defp http_01(_absent), do: nil

  defp matching(fields) do
    url = HTTP.field(fields, "url")
    token = HTTP.field(fields, "token")

    if HTTP.field(fields, "type") == @type_http_01 and is_binary(url) and is_binary(token) do
      %{url: url, token: token, status: HTTP.field(fields, "status") || "pending"}
    end
  end
end
