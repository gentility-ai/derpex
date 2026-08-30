# Adapted from Tailscale's DERP HTTP handler tests.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.HTTP1Test do
  use ExUnit.Case, async: true

  alias Derpex.HTTP1
  alias Derpex.HTTP1.Request
  alias Derpex.Test.ChallengeServer

  @challenge_path "/.well-known/acme-challenge/tok"
  @server_public :binary.copy(<<0xAB>>, 32)
  @operations_token "0123456789abcdef0123456789abcdef"

  test "returns successful CORS probes on both upstream paths" do
    for path <- ["/derp/probe", "/derp/latency-check"] do
      assert {:response, response} = HTTP1.route(request("GET", path), @server_public)
      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 200 OK\r\n"
      assert IO.iodata_to_binary(response) =~ "Access-Control-Allow-Origin: *\r\n"
    end
  end

  test "emits the exact native DERP 101 response" do
    request = request("GET", "/derp", [{"upgrade", "DERP"}, {"ideal-node", "region-a"}])

    assert {:upgrade, :derp, response, %{ideal_node: "region-a"}} =
             HTTP1.route(request, @server_public)

    assert IO.iodata_to_binary(response) ==
             "HTTP/1.1 101 Switching Protocols\r\n" <>
               "Upgrade: DERP\r\n" <>
               "Connection: Upgrade\r\n" <>
               "Derp-Version: 2\r\n" <>
               "Derp-Public-Key: #{Base.encode16(@server_public, case: :lower)}\r\n\r\n"
  end

  test "normalizes absolute-form DERP targets like Go net/http" do
    request =
      request(
        "POST",
        "https://127.0.0.1:4443/derp?client=rust",
        [{"upgrade", "DERP"}]
      )

    assert Request.path(request) == "/derp"
    assert Request.query_param(request, "client") == "rust"

    assert {:upgrade, :derp, response, _metadata} = HTTP1.route(request, @server_public)
    assert IO.iodata_to_binary(response) =~ "HTTP/1.1 101 Switching Protocols\r\n"
  end

  test "suppresses only the HTTP response for fast start" do
    request =
      request("GET", "/derp", [{"upgrade", "derp"}, {"derp-fast-start", "1"}])

    assert HTTP1.route(request, @server_public) ==
             {:upgrade, :derp, nil, %{ideal_node: nil}}
  end

  test "negotiates only a valid WebSocket request with the derp subprotocol" do
    key = Base.encode64(:binary.copy(<<7>>, 16))

    request =
      request("GET", "/derp", [
        {"upgrade", "websocket"},
        {"connection", "keep-alive, Upgrade"},
        {"sec-websocket-version", "13"},
        {"sec-websocket-key", key},
        {"sec-websocket-protocol", "chat, derp"}
      ])

    assert {:upgrade, :websocket, response, %{ideal_node: nil}} =
             HTTP1.route(request, @server_public)

    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 101 Switching Protocols\r\n"
    assert response =~ "Sec-WebSocket-Protocol: derp\r\n"

    assert response =~
             "Sec-WebSocket-Accept: #{Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))}\r\n"

    invalid = %{request | headers: List.keydelete(request.headers, "sec-websocket-key", 0)}
    assert {:response, invalid_response} = HTTP1.route(invalid, @server_public)
    assert IO.iodata_to_binary(invalid_response) =~ "HTTP/1.1 400 Bad Request\r\n"
  end

  test "preserves legacy native DERP for websocket upgrades without the derp subprotocol" do
    request = request("GET", "/derp", [{"upgrade", "websocket"}])
    assert {:upgrade, :derp, response, _metadata} = HTTP1.route(request, @server_public)
    assert IO.iodata_to_binary(response) =~ "Upgrade: DERP\r\n"
  end

  test "closes a WebSocket that offers no exact derp subprotocol with a policy violation" do
    key = Base.encode64(:binary.copy(<<7>>, 16))

    # Upstream routes into websocket.Accept on a substring test, negotiates no
    # subprotocol, then closes because Conn.Subprotocol() is not exactly "derp".
    for offer <- ["notderp", "derp2", "derpx, notderp"] do
      assert {:response, response} =
               HTTP1.route(websocket_request(key, offer), @server_public)

      response = IO.iodata_to_binary(response)
      assert response =~ "HTTP/1.1 101 Switching Protocols\r\n"
      refute response =~ "Sec-WebSocket-Protocol"

      assert String.ends_with?(
               response,
               <<0x88, 40, 1008::unsigned-big-16>> <> "client must speak the derp subprotocol"
             )
    end
  end

  test "negotiates the exact derp subprotocol out of a comma separated offer" do
    key = Base.encode64(:binary.copy(<<7>>, 16))

    assert {:upgrade, :websocket, response, _metadata} =
             HTTP1.route(websocket_request(key, "foo, derp"), @server_public)

    assert IO.iodata_to_binary(response) =~ "Sec-WebSocket-Protocol: derp\r\n"
  end

  test "echoes the client spelling of a case-folded derp offer before rejecting it" do
    key = Base.encode64(:binary.copy(<<7>>, 16))

    assert {:response, response} =
             HTTP1.route(websocket_request(key, "derpish, Derp"), @server_public)

    response = IO.iodata_to_binary(response)
    assert response =~ "Sec-WebSocket-Protocol: Derp\r\n"
    assert response =~ "client must speak the derp subprotocol"
  end

  # Every expected byte string below was captured from a Go 1.27 http.Server
  # answering the same raw request head.
  test "answers each malformed Host exactly as Go net/http does" do
    cases = [
      {[], "GET", "400 Bad Request: missing required Host header"},
      {[{"host", "a.example"}, {"host", "b.example"}], "GET", "400 Bad Request"},
      {[{"host", "bad host"}], "GET", "400 Bad Request: malformed Host header"},
      {[{"host", "bad\thost"}], "GET", "400 Bad Request: malformed Host header"},
      {[{"host", "user@host"}], "GET", "400 Bad Request: malformed Host header"},
      {[{"host", "bad host"}], "CONNECT", "400 Bad Request: malformed Host header"}
    ]

    for {headers, method, status} <- cases do
      request = %Request{
        method: method,
        target: "/derp/probe",
        version: "HTTP/1.1",
        headers: headers
      }

      assert {:response, response} = HTTP1.route(request, @server_public)

      assert IO.iodata_to_binary(response) ==
               "HTTP/1.1 " <>
                 status <>
                 "\r\nContent-Type: text/plain; charset=utf-8\r\n" <>
                 "Connection: close\r\n\r\n" <> status
    end
  end

  test "accepts every Host shape Go net/http lets through" do
    accepted = [
      {"HTTP/1.1", "GET", [{"host", ""}], "HTTP/1.1 200 OK\r\n"},
      {"HTTP/1.1", "GET", [{"host", "h.example:8443"}], "HTTP/1.1 200 OK\r\n"},
      {"HTTP/1.1", "GET", [{"host", "bad_host"}], "HTTP/1.1 200 OK\r\n"},
      {"HTTP/1.0", "GET", [], "HTTP/1.1 200 OK\r\n"},
      # CONNECT is exempt from the Host requirement, so it reaches the probe
      # handler and is turned away there on method rather than on Host.
      {"HTTP/1.1", "CONNECT", [], "HTTP/1.1 405 Method Not Allowed\r\n"}
    ]

    for {version, method, headers, status_line} <- accepted do
      request = %Request{
        method: method,
        target: "/derp/probe",
        version: version,
        headers: headers
      }

      assert {:response, response} = HTTP1.route(request, @server_public)
      assert IO.iodata_to_binary(response) =~ status_line
    end
  end

  test "negotiates a derp token carried by a second subprotocol header" do
    key = Base.encode64(:binary.copy(<<7>>, 16))

    request =
      request("GET", "/derp", [
        {"upgrade", "websocket"},
        {"connection", "Upgrade"},
        {"sec-websocket-version", "13"},
        {"sec-websocket-key", key},
        {"sec-websocket-protocol", "derpx"},
        {"sec-websocket-protocol", "derp"}
      ])

    assert {:upgrade, :websocket, response, _metadata} = HTTP1.route(request, @server_public)

    response = IO.iodata_to_binary(response)
    assert response =~ "Sec-WebSocket-Protocol: derp\r\n"
    refute response =~ "client must speak the derp subprotocol"
  end

  defp websocket_request(key, subprotocol) do
    request("GET", "/derp", [
      {"upgrade", "websocket"},
      {"connection", "Upgrade"},
      {"sec-websocket-version", "13"},
      {"sec-websocket-key", key},
      {"sec-websocket-protocol", subprotocol}
    ])
  end

  test "requires an upgrade on other DERP paths" do
    assert {:response, response} = HTTP1.route(request("GET", "/derp/sdf"), @server_public)
    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 426 Upgrade Required\r\n"
    assert response =~ "DERP requires connection upgrade\n"
  end

  test "serves generate_204 with a validated challenge" do
    request = request("GET", "/generate_204", [{"x-tailscale-challenge", "abc-123:_"}])
    assert {:response, response} = HTTP1.route(request, @server_public)
    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 204 No Content\r\n"
    assert response =~ "X-Tailscale-Response: response abc-123:_\r\n"

    assert response =~
             "Cache-Control: no-cache, no-store, must-revalidate, no-transform, max-age=0"
  end

  test "matches every upstream generate_204 challenge case" do
    cases = [
      {nil, nil},
      {"", nil},
      {"input", "response input"},
      {"ts_derp99b.tailscale.com", "response ts_derp99b.tailscale.com"},
      {"foo\0bar", nil},
      {"foo bar", nil},
      {:binary.copy("x", 65), nil}
    ]

    for {challenge, expected} <- cases do
      headers = if challenge == nil, do: [], else: [{"x-tailscale-challenge", challenge}]

      assert {:response, response} =
               HTTP1.route(request("GET", "/generate_204", headers), @server_public)

      response = IO.iodata_to_binary(response)
      assert response =~ "HTTP/1.1 204 No Content\r\n"

      if expected do
        assert response =~ "X-Tailscale-Response: #{expected}\r\n"
      else
        refute response =~ "X-Tailscale-Response:"
      end
    end
  end

  test "serves public health and readiness without topology details" do
    options = [operations: [enabled: true]]

    assert {:response, disabled} = HTTP1.route(request("GET", "/healthz"), @server_public)
    assert IO.iodata_to_binary(disabled) =~ "HTTP/1.1 404 Not Found\r\n"

    for path <- ["/healthz", "/readyz"] do
      assert {:response, response} = HTTP1.route(request("GET", path), @server_public, options)

      assert IO.iodata_to_binary(response) ==
               "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nok\n"
    end
  end

  test "keeps metrics and consistency disabled until bearer authentication is configured" do
    assert {:response, disabled} = HTTP1.route(request("GET", "/metrics"), @server_public)
    assert IO.iodata_to_binary(disabled) =~ "HTTP/1.1 404 Not Found\r\n"

    options = [operations: [enabled: true, token: @operations_token]]

    assert {:response, unauthorized} =
             HTTP1.route(request("GET", "/metrics"), @server_public, options)

    assert IO.iodata_to_binary(unauthorized) =~ "HTTP/1.1 401 Unauthorized\r\n"

    headers = [{"authorization", "Bearer " <> @operations_token}]

    assert {:response, metrics} =
             HTTP1.route(request("GET", "/metrics", headers), @server_public, options)

    metrics = IO.iodata_to_binary(metrics)
    assert metrics =~ "HTTP/1.1 200 OK\r\n"
    assert metrics =~ "derp_gauge_current_connections "

    assert {:response, check} =
             HTTP1.route(request("GET", "/debug/check", headers), @server_public, options)

    assert IO.iodata_to_binary(check) =~ "derp.Server ConsistencyCheck okay"
  end

  test "protects each baseline debug route with upstream source rules" do
    local_options = [debug: [remote_ip: {127, 0, 0, 1}]]

    for path <- ["/debug/", "/debug/vars", "/debug/varz", "/debug/check"] do
      assert {:response, response} =
               HTTP1.route(request("GET", path), @server_public, local_options)

      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 200 OK\r\n"

      assert {:response, response} =
               HTTP1.route(request("POST", path), @server_public, local_options)

      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 200 OK\r\n"
    end

    public_options = [debug: [remote_ip: {203, 0, 113, 8}]]

    assert {:response, forbidden} =
             HTTP1.route(request("GET", "/debug/vars"), @server_public, public_options)

    forbidden = IO.iodata_to_binary(forbidden)
    assert forbidden =~ "HTTP/1.1 403 Forbidden\r\n"
    assert forbidden =~ "\r\n\r\ndebug access denied\n"

    forwarded = [{"x-forwarded-for", "198.51.100.9"}]

    assert {:response, forbidden} =
             HTTP1.route(request("GET", "/debug/check", forwarded), @server_public, local_options)

    assert IO.iodata_to_binary(forbidden) =~ "HTTP/1.1 403 Forbidden\r\n"
  end

  test "accepts the product operations bearer on every baseline debug route" do
    options = [
      debug: [remote_ip: {203, 0, 113, 8}],
      operations: [enabled: true, token: @operations_token]
    ]

    headers = [
      {"authorization", "Bearer " <> @operations_token},
      {"x-forwarded-for", "198.51.100.9"}
    ]

    for path <- ["/debug/", "/debug/vars", "/debug/varz", "/debug/check"] do
      assert {:response, response} =
               HTTP1.route(request("GET", path, headers), @server_public, options)

      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 200 OK\r\n"
    end
  end

  test "starts an independently authorized chunked traffic stream" do
    options = [debug: [remote_ip: {127, 0, 0, 1}, traffic: [interval_ms: 25]]]

    assert {:stream, :debug_traffic, response, [interval_ms: 25]} =
             HTTP1.route(request("GET", "/debug/traffic"), @server_public, options)

    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 200 OK\r\n"
    assert response =~ "Transfer-Encoding: chunked\r\n"

    forwarded = [{"x-forwarded-for", "198.51.100.9"}]

    assert {:response, forbidden} =
             HTTP1.route(request("GET", "/debug/traffic", forwarded), @server_public, options)

    assert IO.iodata_to_binary(forbidden) =~ "HTTP/1.1 403 Forbidden\r\n"
  end

  test "serves the upstream robots exclusion body" do
    assert {:response, response} = HTTP1.route(request("GET", "/robots.txt"), @server_public)
    assert IO.iodata_to_binary(response) =~ "User-agent: *\nDisallow: /\n"
  end

  describe "HTTP-01 challenge route" do
    setup do
      store = start_supervised!(ChallengeServer)
      :ok = ChallengeServer.put_challenge(store, @challenge_path, "tok.thumbprint")
      {:ok, options: [acme_challenges: {ChallengeServer, store}]}
    end

    test "serves a published key authorization as plain text", context do
      assert {:response, response} =
               HTTP1.route(request("GET", @challenge_path), @server_public, context.options)

      response = IO.iodata_to_binary(response)
      assert response =~ "HTTP/1.1 200 OK\r\n"
      assert response =~ "Content-Type: text/plain\r\n"
      assert String.ends_with?(response, "\r\n\r\ntok.thumbprint")
    end

    test "keeps a key authorization out of every cache", context do
      assert {:response, response} =
               HTTP1.route(request("GET", @challenge_path), @server_public, context.options)

      assert IO.iodata_to_binary(response) =~ "Cache-Control: no-store\r\n"
    end

    test "refuses a token outside the base64url alphabet without a lookup", context do
      malformed = [
        "/.well-known/acme-challenge/../../etc/passwd",
        "/.well-known/acme-challenge/tok%2e%2e",
        "/.well-known/acme-challenge/tok/nested",
        "/.well-known/acme-challenge/",
        "/.well-known/acme-challenge/" <> String.duplicate("t", 129)
      ]

      for path <- malformed do
        assert {:response, response} =
                 HTTP1.route(request("GET", path), @server_public, context.options)

        assert IO.iodata_to_binary(response) =~ "HTTP/1.1 404 Not Found\r\n",
               "#{path} was not refused"
      end
    end

    test "answers an unknown token with the same 404 any unknown path gets", context do
      unknown = "/.well-known/acme-challenge/other"

      assert {:response, response} =
               HTTP1.route(request("GET", unknown), @server_public, context.options)

      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 404 Not Found\r\n"
    end

    test "refuses a method other than GET", context do
      assert {:response, response} =
               HTTP1.route(request("POST", @challenge_path), @server_public, context.options)

      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 405 Method Not Allowed\r\n"
    end
  end

  describe "the plaintext listener" do
    setup do
      store = start_supervised!(ChallengeServer)
      :ok = ChallengeServer.put_challenge(store, @challenge_path, "tok.thumbprint")

      {:ok,
       options: [
         acme_challenges: {ChallengeServer, store},
         plaintext: [allow_upgrade: false]
       ]}
    end

    test "answers the challenge path and the unauthenticated probes", context do
      for path <- [@challenge_path, "/derp/probe", "/derp/latency-check", "/generate_204"] do
        assert {:response, response} =
                 HTTP1.route(request("GET", path), @server_public, context.options)

        response = IO.iodata_to_binary(response)
        refute response =~ "HTTP/1.1 302 Found\r\n", "#{path} was redirected"
        refute response =~ "HTTP/1.1 404 Not Found\r\n", "#{path} was not served"
      end
    end

    test "redirects everything else to HTTPS, preserving the target", context do
      for path <- ["/", "/robots.txt", "/bootstrap-dns?domain=x", "/debug/vars"] do
        assert {:response, response} =
                 HTTP1.route(request("GET", path), @server_public, context.options)

        response = IO.iodata_to_binary(response)
        assert response =~ "HTTP/1.1 302 Found\r\n"
        assert response =~ "Location: https://derp.example#{path}\r\n"
        assert response =~ "Cache-Control: no-store\r\n"
      end
    end

    test "tells a non-GET request to use HTTPS", context do
      assert {:response, response} =
               HTTP1.route(request("POST", "/"), @server_public, context.options)

      response = IO.iodata_to_binary(response)
      assert response =~ "HTTP/1.1 400 Bad Request\r\n"
      assert response =~ "Use HTTPS\n"
    end

    test "refuses a cleartext DERP upgrade unless it is opted into", context do
      upgrade = request("GET", "/derp", [{"upgrade", "DERP"}])

      assert {:response, response} = HTTP1.route(upgrade, @server_public, context.options)
      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 302 Found\r\n"

      allowed = Keyword.put(context.options, :plaintext, allow_upgrade: true)

      assert {:upgrade, :derp, _response, _metadata} =
               HTTP1.route(upgrade, @server_public, allowed)
    end
  end

  test "the challenge path is not special without a challenge source" do
    assert {:response, response} = HTTP1.route(request("GET", @challenge_path), @server_public)
    assert IO.iodata_to_binary(response) =~ "HTTP/1.1 404 Not Found\r\n"
  end

  defp request(method, path, headers \\ []) do
    headers =
      if List.keymember?(headers, "host", 0),
        do: headers,
        else: [{"host", "derp.example"} | headers]

    %Request{method: method, target: path, version: "HTTP/1.1", headers: headers}
  end
end
