# This module implements HTTP behavior from Tailscale's DERP handler.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.HTTP1 do
  @moduledoc "HTTP routing for DERP upgrade, probes, and captive-portal checks."

  alias Derpex.BootstrapDNS
  alias Derpex.Handshake
  alias Derpex.HomePage
  alias Derpex.HTTP1.Request
  alias Derpex.HTTP1.Response

  @doc "Routes a parsed request without consuming bytes read past its headers."
  @spec route(Request.t(), binary(), keyword()) ::
          {:upgrade, :derp | :websocket, nil | iodata(), map()} | {:response, iodata()}
  def route(%Request{} = request, server_public_key, options \\ []) do
    case Request.path(request) do
      path when path in ["/derp/probe", "/derp/latency-check"] ->
        probe(request)

      "/generate_204" ->
        no_content(request)

      "/bootstrap-dns" ->
        bootstrap_dns(request, options)

      "/" ->
        home_page(options)

      path when path == "/derp" or binary_part(path, 0, min(byte_size(path), 6)) == "/derp/" ->
        upgrade(request, server_public_key)

      _path ->
        {:response, Response.encode(404, [], "404 page not found\n")}
    end
  end

  defp home_page(options) do
    body = options |> Keyword.get(:home_page, []) |> HomePage.render()
    {:response, Response.encode(200, [{"Content-Type", "text/html; charset=utf-8"}], body)}
  end

  defp bootstrap_dns(request, options) do
    server = Keyword.get(options, :bootstrap_dns, BootstrapDNS)
    remote_address = Keyword.get(options, :remote_address, "")
    query = Request.query_param(request, "q") || ""
    body = server |> BootstrapDNS.lookup(query, remote_address) |> :json.encode()

    {:response,
     Response.encode(
       200,
       [{"Content-Type", "application/json"}, {"Connection", "close"}],
       body
     )}
  end

  defp probe(%Request{method: method}) when method in ["GET", "HEAD"] do
    {:response, Response.encode(200, [{"Access-Control-Allow-Origin", "*"}])}
  end

  defp probe(_request) do
    {:response,
     Response.encode(
       405,
       [{"Content-Type", "text/plain; charset=utf-8"}, {"X-Content-Type-Options", "nosniff"}],
       "bogus probe method\n"
     )}
  end

  defp no_content(request) do
    headers = [
      {"Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0"}
    ]

    headers =
      case Request.header(request, "x-tailscale-challenge") do
        challenge when is_binary(challenge) -> maybe_add_challenge_response(headers, challenge)
        nil -> headers
      end

    {:response, Response.encode(204, headers)}
  end

  defp maybe_add_challenge_response(headers, challenge) do
    if byte_size(challenge) in 1..64 and valid_challenge?(challenge) do
      [{"X-Tailscale-Response", "response " <> challenge} | headers]
    else
      headers
    end
  end

  defp valid_challenge?(<<>>), do: true

  defp valid_challenge?(<<byte, rest::binary>>)
       when byte in ?a..?z or byte in ?A..?Z or byte in ?0..?9 or byte in ~c".-_:" do
    valid_challenge?(rest)
  end

  defp valid_challenge?(_challenge), do: false

  defp upgrade(request, server_public_key) do
    case request |> Request.header("upgrade") |> downcase_header() do
      "derp" -> native_upgrade(request, server_public_key)
      "websocket" -> websocket_or_legacy_upgrade(request, server_public_key)
      _other -> upgrade_required()
    end
  end

  defp native_upgrade(request, <<server_public_key::binary-size(32)>>) do
    response =
      if Request.header(request, "derp-fast-start") == "1" do
        nil
      else
        [
          "HTTP/1.1 101 Switching Protocols\r\n",
          "Upgrade: DERP\r\n",
          "Connection: Upgrade\r\n",
          "Derp-Version: ",
          Integer.to_string(Handshake.protocol_version()),
          "\r\n",
          "Derp-Public-Key: ",
          Base.encode16(server_public_key, case: :lower),
          "\r\n\r\n"
        ]
      end

    {:upgrade, :derp, response, upgrade_metadata(request)}
  end

  defp websocket_or_legacy_upgrade(request, server_public_key) do
    case Request.header(request, "sec-websocket-protocol") do
      protocols when is_binary(protocols) ->
        if String.contains?(protocols, "derp") do
          websocket_upgrade(request)
        else
          native_upgrade(request, server_public_key)
        end

      nil ->
        native_upgrade(request, server_public_key)
    end
  end

  defp websocket_upgrade(request) do
    with true <- request.method == "GET",
         true <- connection_upgrade?(Request.header(request, "connection")),
         "13" <- Request.header(request, "sec-websocket-version"),
         key when is_binary(key) <- Request.header(request, "sec-websocket-key"),
         {:ok, decoded_key} <- Base.decode64(key),
         true <- byte_size(decoded_key) == 16 do
      accept = Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

      response = [
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: ",
        accept,
        "\r\n",
        "Sec-WebSocket-Protocol: derp\r\n\r\n"
      ]

      {:upgrade, :websocket, response, upgrade_metadata(request)}
    else
      _invalid ->
        {:response, Response.encode(400, [], "Bad Request\n")}
    end
  end

  defp connection_upgrade?(nil), do: false

  defp connection_upgrade?(value) do
    value
    |> String.split(",")
    |> Enum.any?(&(String.trim(&1) |> String.downcase(:ascii) == "upgrade"))
  end

  defp upgrade_required do
    {:response,
     Response.encode(
       426,
       [{"Content-Type", "text/plain; charset=utf-8"}, {"X-Content-Type-Options", "nosniff"}],
       "DERP requires connection upgrade\n"
     )}
  end

  defp upgrade_metadata(request) do
    %{ideal_node: Request.header(request, "ideal-node")}
  end

  defp downcase_header(nil), do: nil
  defp downcase_header(value), do: String.downcase(value, :ascii)
end
