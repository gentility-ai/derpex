# This module implements HTTP behavior from Tailscale's DERP handler.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.HTTP1 do
  @moduledoc "HTTP routing for DERP upgrade, probes, and captive-portal checks."

  alias Derpex.BootstrapDNS
  alias Derpex.Debug.Access
  alias Derpex.Handshake
  alias Derpex.HomePage
  alias Derpex.HTTP1.Request
  alias Derpex.HTTP1.Response
  alias Derpex.Operations
  alias Derpex.WebSocket.Frame

  @subprotocol_violation "client must speak the derp subprotocol"
  @policy_violation_status 1008
  @error_headers "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

  # httpguts.ValidHostHeader's byte set, minus the alphanumerics handled by range.
  @host_punctuation ~c"!$%&'()*+,-.:;=[]_~"

  @doc "Routes a parsed request without consuming bytes read past its headers."
  @spec route(Request.t(), binary(), keyword()) ::
          {:upgrade, :derp | :websocket, nil | iodata(), map()}
          | {:stream, :debug_traffic, iodata(), keyword()}
          | {:response, iodata()}
  def route(%Request{} = request, server_public_key, options \\ []) do
    case host_error(request) do
      nil ->
        request
        |> Request.path()
        |> route_path(request, server_public_key, options)

      error ->
        reject_host(error)
    end
  end

  # Go's net/http validates Host while reading the head, before any handler
  # runs. Duplicates are rejected first, then a missing Host on HTTP/1.1
  # (CONNECT excepted), then a value outside ValidHostHeader's byte set. An
  # empty Host value is a present header and stays legal.
  defp host_error(%Request{} = request) do
    case Request.header_values(request, "host") do
      [host] -> if valid_host?(host), do: nil, else: :malformed
      [] -> if host_mandatory?(request), do: :missing, else: nil
      _duplicates -> :too_many
    end
  end

  defp host_mandatory?(%Request{version: "HTTP/1.1", method: method}), do: method != "CONNECT"
  defp host_mandatory?(%Request{}), do: false

  defp valid_host?(<<>>), do: true

  defp valid_host?(<<byte, rest::binary>>)
       when byte in ?0..?9 or byte in ?A..?Z or byte in ?a..?z or byte in @host_punctuation do
    valid_host?(rest)
  end

  defp valid_host?(_host), do: false

  # Byte-for-byte the responses Go's conn.serve writes for these three errors:
  # the first two carry a statusError suffix, "too many Host headers" does not.
  defp reject_host(:missing), do: host_status("400 Bad Request: missing required Host header")
  defp reject_host(:malformed), do: host_status("400 Bad Request: malformed Host header")
  defp reject_host(:too_many), do: host_status("400 Bad Request")

  defp host_status(status), do: {:response, ["HTTP/1.1 ", status, @error_headers, status]}

  defp route_path(path, request, _server_public_key, _options)
       when path in ["/derp/probe", "/derp/latency-check"],
       do: probe(request)

  defp route_path("/generate_204", request, _server_public_key, _options),
    do: no_content(request)

  defp route_path("/healthz", request, _server_public_key, options),
    do: health(request, :live, options)

  defp route_path("/readyz", request, _server_public_key, options),
    do: health(request, :ready, options)

  defp route_path("/metrics", request, _server_public_key, options),
    do: protected(request, options, &metrics/0)

  defp route_path("/debug/check", request, _server_public_key, options),
    do: debug_protected(request, options, &consistency_check/0)

  defp route_path("/debug/vars", request, _server_public_key, options),
    do: debug_protected(request, options, &expvar/0)

  defp route_path("/debug/varz", request, _server_public_key, options),
    do: debug_protected(request, options, &metrics/0)

  defp route_path("/debug/traffic", request, _server_public_key, options),
    do: debug_protected(request, options, fn -> debug_traffic(options) end)

  defp route_path("/debug/", request, _server_public_key, options),
    do: debug_protected(request, options, &debug_index/0)

  defp route_path("/robots.txt", request, _server_public_key, _options), do: robots(request)

  defp route_path("/bootstrap-dns", request, _server_public_key, options),
    do: bootstrap_dns(request, options)

  defp route_path("/", _request, _server_public_key, options), do: home_page(options)

  defp route_path(path, request, server_public_key, _options)
       when path == "/derp" or binary_part(path, 0, min(byte_size(path), 6)) == "/derp/",
       do: upgrade(request, server_public_key)

  defp route_path(_path, _request, _server_public_key, _options),
    do: {:response, Response.encode(404, [], "404 page not found\n")}

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

  defp health(request, kind, options) do
    operations = Keyword.get(options, :operations, [])

    if Operations.enabled?(operations),
      do: enabled_health(request, kind),
      else: {:response, Response.encode(404, [], "404 page not found\n")}
  end

  defp enabled_health(%Request{method: "GET"}, kind) do
    case Operations.health(kind) do
      :ok ->
        {:response, Response.encode(200, [{"Content-Type", "text/plain"}], "ok\n")}

      {:error, _reason} ->
        status = if kind == :live, do: 500, else: 503
        body = if kind == :live, do: "unhealthy\n", else: "not ready\n"
        {:response, Response.encode(status, [{"Content-Type", "text/plain"}], body)}
    end
  end

  defp enabled_health(_request, _kind), do: method_not_allowed()

  defp protected(%Request{method: "GET"} = request, options, callback) do
    case Operations.authorize(request, Keyword.get(options, :operations, [])) do
      :authorized ->
        callback.()

      :disabled ->
        {:response, Response.encode(404, [], "404 page not found\n")}

      :unauthorized ->
        {:response,
         Response.encode(
           401,
           [{"Content-Type", "text/plain"}, {"WWW-Authenticate", "Bearer"}],
           "unauthorized\n"
         )}
    end
  end

  defp protected(_request, _options, _callback), do: method_not_allowed()

  defp debug_protected(%Request{} = request, options, callback) do
    debug = Keyword.get(options, :debug, [])
    operations = Keyword.get(options, :operations, [])

    case Access.authorize(request, debug, operations) do
      :authorized -> callback.()
      :unauthorized -> debug_forbidden()
    end
  end

  defp metrics do
    {:response,
     Response.encode(
       200,
       [{"Content-Type", "text/plain; version=0.0.4; charset=utf-8"}],
       Operations.prometheus()
     )}
  end

  defp expvar do
    {:response,
     Response.encode(
       200,
       [{"Content-Type", "application/json; charset=utf-8"}],
       Operations.expvar_json()
     )}
  end

  defp debug_index do
    body =
      "<html><body><h1>derpex debug</h1><ul>" <>
        "<li><a href=\"/debug/vars\">/debug/vars</a> (Metrics (Go))</li>" <>
        "<li><a href=\"/debug/varz\">/debug/varz</a> (Metrics (Prometheus))</li>" <>
        "<li><a href=\"/debug/check\">/debug/check</a> (Consistency check)</li>" <>
        "<li><a href=\"/debug/traffic\">/debug/traffic</a> (Traffic check)</li>" <>
        "</ul></body></html>"

    {:response, Response.encode(200, [{"Content-Type", "text/html; charset=utf-8"}], body)}
  end

  defp debug_forbidden do
    {:response,
     Response.encode(
       403,
       [{"Content-Type", "text/plain; charset=utf-8"}, {"X-Content-Type-Options", "nosniff"}],
       "debug access denied\n"
     )}
  end

  defp debug_traffic(options) do
    response =
      Response.encode(
        200,
        [
          {"Content-Type", "text/plain; charset=utf-8"},
          {"Transfer-Encoding", "chunked"}
        ]
      )

    debug = Keyword.get(options, :debug, [])
    {:stream, :debug_traffic, response, Keyword.get(debug, :traffic, [])}
  end

  defp consistency_check do
    case Operations.consistency_check() do
      :ok ->
        {:response, Response.encode(200, [], "derp.Server ConsistencyCheck okay")}

      {:error, reason} ->
        {:response, Response.encode(500, [{"Content-Type", "text/plain"}], reason <> "\n")}
    end
  end

  defp robots(%Request{method: "GET"}) do
    {:response,
     Response.encode(200, [{"Content-Type", "text/plain"}], "User-agent: *\nDisallow: /\n")}
  end

  defp robots(_request), do: method_not_allowed()

  defp method_not_allowed do
    {:response,
     Response.encode(
       405,
       [{"Content-Type", "text/plain; charset=utf-8"}, {"X-Content-Type-Options", "nosniff"}],
       "method not allowed\n"
     )}
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

  # Upstream picks the WebSocket path on a case-sensitive substring test, then
  # lets coder/websocket negotiate one exact (case-insensitive) token out of the
  # offer. Anything else stays on the legacy native-DERP path.
  defp websocket_or_legacy_upgrade(request, server_public_key) do
    case Request.header(request, "sec-websocket-protocol") do
      protocols when is_binary(protocols) ->
        if String.contains?(protocols, "derp") do
          websocket_upgrade(request, negotiated_subprotocol(request))
        else
          native_upgrade(request, server_public_key)
        end

      nil ->
        native_upgrade(request, server_public_key)
    end
  end

  # The path gate above reads only the first header value, as Go's Header.Get
  # does, but negotiation unions the tokens of every value like headerTokens.
  defp negotiated_subprotocol(request) do
    request
    |> Request.header_values("sec-websocket-protocol")
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&String.trim/1)
    |> Enum.find(&(String.downcase(&1, :ascii) == "derp"))
  end

  defp websocket_upgrade(request, subprotocol) do
    with true <- request.method == "GET",
         true <- connection_upgrade?(Request.header(request, "connection")),
         "13" <- Request.header(request, "sec-websocket-version"),
         key when is_binary(key) <- Request.header(request, "sec-websocket-key"),
         {:ok, decoded_key} <- Base.decode64(key),
         true <- byte_size(decoded_key) == 16 do
      accept = Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
      handshake = websocket_handshake(accept, subprotocol)

      # Upstream compares the negotiated subprotocol to "derp" byte for byte
      # after the handshake, so a near miss gets a 101 and then a close.
      if subprotocol == "derp" do
        {:upgrade, :websocket, handshake, upgrade_metadata(request)}
      else
        {:response,
         [handshake, Frame.encode_close(@policy_violation_status, @subprotocol_violation)]}
      end
    else
      _invalid ->
        {:response, Response.encode(400, [], "Bad Request\n")}
    end
  end

  defp websocket_handshake(accept, subprotocol) do
    [
      "HTTP/1.1 101 Switching Protocols\r\n",
      "Upgrade: websocket\r\n",
      "Connection: Upgrade\r\n",
      "Sec-WebSocket-Accept: ",
      accept,
      "\r\n",
      subprotocol_header(subprotocol),
      "\r\n"
    ]
  end

  defp subprotocol_header(nil), do: []
  defp subprotocol_header(subprotocol), do: ["Sec-WebSocket-Protocol: ", subprotocol, "\r\n"]

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
