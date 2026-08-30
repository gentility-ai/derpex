# This module implements the order handling of golang.org/x/crypto/acme's
# rfc8555.go, as vendored at ../tailscale/tempfork/acme.
# Copyright (c) 2015 The Go Authors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.Order do
  @moduledoc """
  ACME orders: one identifier per order, optionally under a named profile.

  `cmd/derper` orders a certificate for exactly one identifier — an IP address
  for the IP certificate path, a DNS name for the hostname path — so nothing
  here builds a multi-identifier order. The `profile` member is the RFC 8555
  profiles extension, which is how the six-day `shortlived` certificate is
  requested; a certificate authority that does not advertise it must not be
  sent one, because it would quietly issue under its default profile instead.
  """

  alias Derpex.ACME.HTTP

  @type subject :: {:ip, binary()} | {:dns, binary()}
  @type t :: %{
          url: binary() | nil,
          status: binary(),
          authorizations: [binary()],
          finalize: binary() | nil,
          certificate: binary() | nil
        }

  @doc "Returns the `newOrder` payload for one identifier."
  @spec payload(subject(), binary() | nil) :: map()
  def payload(identifier, profile \\ nil) do
    %{"identifiers" => [wire_identifier(identifier)]}
    |> profile(profile)
  end

  @doc "Returns the `finalize` payload carrying a DER certificate request."
  @spec finalize_payload(binary()) :: map()
  def finalize_payload(csr_der) do
    %{"csr" => Base.url_encode64(csr_der, padding: false)}
  end

  @doc "Parses an order response, taking its URL from `Location` when present."
  @spec parse(HTTP.response()) :: {:ok, t()} | {:error, term()}
  def parse(response) do
    with {:ok, fields} <- HTTP.decode(response) do
      {:ok,
       %{
         url: HTTP.header(response, "location"),
         status: HTTP.field(fields, "status") || "unknown",
         authorizations: strings(HTTP.field(fields, "authorizations")),
         finalize: HTTP.field(fields, "finalize"),
         certificate: HTTP.field(fields, "certificate")
       }}
    end
  end

  @doc """
  Classifies an order's status for polling.

  RFC 8555 orders move `pending` to `ready` once every authorization is valid,
  and `ready` to `valid` once the certificate is issued. `invalid` is terminal.
  """
  @spec settled(t()) :: :ready | :issued | :pending | {:error, term()}
  def settled(%{status: "valid"}), do: :issued
  def settled(%{status: "ready"}), do: :ready
  def settled(%{status: "invalid"} = order), do: {:error, {:order_invalid, order.url}}
  def settled(_order), do: :pending

  defp wire_identifier({:ip, value}), do: %{"type" => "ip", "value" => value}
  defp wire_identifier({:dns, value}), do: %{"type" => "dns", "value" => value}

  defp profile(payload, nil), do: payload
  defp profile(payload, ""), do: payload
  defp profile(payload, profile), do: Map.put(payload, "profile", profile)

  defp strings(values) when is_list(values), do: Enum.filter(values, &is_binary/1)
  defp strings(_absent), do: []
end
