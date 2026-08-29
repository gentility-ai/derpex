defmodule Derpex.SessionTest do
  use ExUnit.Case, async: true

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake
  alias Derpex.Secret
  alias Derpex.Session

  test "orders standard HTTP upgrade, greeting, and pipelined authentication" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    client_info = %ClientInfo{version: 2}
    {:ok, client_frame} = Handshake.client_info_frame(client_private, server_public, client_info)

    request =
      "GET /derp HTTP/1.1\r\nHost: derp.example\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"

    {:ok, session, [{:set_timeout, :http, 10_000}]} = Session.new(Secret.wrap(server_private))

    assert {:ok, session, actions} =
             Session.receive_data(session, IO.iodata_to_binary([request, client_frame]))

    assert [
             {:cancel_timeout, :http},
             {:send, http_response},
             {:send, greeting},
             {:set_timeout, :handshake, 10_000},
             {:authenticated, ^client_public, ^client_info, false},
             {:send, _server_info},
             {:register, ^client_public, ^client_info, false},
             {:cancel_timeout, :handshake},
             {:set_timeout, :keep_alive, keep_alive_interval}
           ] = actions

    assert keep_alive_interval in 60_000..64_999

    assert IO.iodata_to_binary(http_response) =~ "HTTP/1.1 101 Switching Protocols"
    assert {:ok, type, 40, _body} = greeting |> IO.iodata_to_binary() |> Frame.decode_header()
    assert type == Frame.type(:server_key)
    assert Session.info(session).phase == :derp
  end

  test "fast start emits no HTTP bytes and keeps the DERP read-ahead" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    request =
      "GET /derp HTTP/1.1\r\nHost: derp.example\r\n" <>
        "Upgrade: DERP\r\nConnection: Upgrade\r\nDerp-Fast-Start: 1\r\n\r\n"

    {:ok, session, _actions} = Session.new(Secret.wrap(server_private))

    assert {:ok, _session, actions} =
             Session.receive_data(session, IO.iodata_to_binary([request, client_frame]))

    assert [{:cancel_timeout, :http}, {:send, greeting} | _rest] = actions
    assert {:ok, type, 40, _body} = greeting |> IO.iodata_to_binary() |> Frame.decode_header()
    assert type == Frame.type(:server_key)
  end

  test "serves finite HTTP requests and closes the session" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, session, _actions} = Session.new(Secret.wrap(server_private))

    assert {:close, session, :http_response, [{:cancel_timeout, :http}, {:send, response}]} =
             Session.receive_data(
               session,
               "GET /derp/probe HTTP/1.1\r\nHost: derp.example\r\n\r\n"
             )

    assert IO.iodata_to_binary(response) =~ "200 OK"
    assert Session.info(session).phase == :closed
  end

  test "keeps an authorized traffic response open as a bounded stream" do
    {_server_public, server_private} = Crypto.generate_keypair()

    {:ok, session, _actions} =
      Session.new(Secret.wrap(server_private),
        debug: [remote_ip: {127, 0, 0, 1}, traffic: [interval_ms: 25]]
      )

    assert {:ok, session,
            [
              {:cancel_timeout, :http},
              {:send, response},
              {:start_debug_traffic, [interval_ms: 25]}
            ]} =
             Session.receive_data(
               session,
               "GET /debug/traffic HTTP/1.1\r\nHost: derp.example\r\n\r\n"
             )

    assert IO.iodata_to_binary(response) =~ "Transfer-Encoding: chunked"
    assert Session.info(session).phase == :debug_traffic
    assert Session.receive_data(session, "ignored request body") == {:ok, session, []}
  end

  test "orders the WebSocket upgrade before framed DERP output" do
    {_server_public, server_private} = Crypto.generate_keypair()
    key = Base.encode64(:binary.copy(<<7>>, 16))

    request =
      "GET /derp HTTP/1.1\r\n" <>
        "Host: derp.example\r\n" <>
        "Upgrade: websocket\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Sec-WebSocket-Version: 13\r\n" <>
        "Sec-WebSocket-Key: #{key}\r\n" <>
        "Sec-WebSocket-Protocol: derp\r\n\r\n"

    {:ok, session, _actions} = Session.new(Secret.wrap(server_private))
    assert {:ok, session, actions} = Session.receive_data(session, request)

    assert [
             {:cancel_timeout, :http},
             {:send, response},
             {:set_wire_mode, :websocket},
             {:send, _greeting},
             {:set_timeout, :handshake, 10_000}
           ] = actions

    assert IO.iodata_to_binary(response) =~ "Sec-WebSocket-Protocol: derp"
    assert Session.info(session).phase == :derp
  end

  test "keeps the server private key and mesh key out of inspected state" do
    {_server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, session, _actions} =
      Session.new(Secret.wrap(server_private), mesh_key: Secret.wrap(mesh_key))

    request =
      "GET /derp HTTP/1.1\r\nHost: derp.example\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"

    {:ok, session, _actions} = Session.receive_data(session, request)

    rendered = inspect(session, limit: :infinity, structs: false, binaries: :as_binaries)

    refute rendered =~ Base.encode16(server_private)
    refute rendered =~ inspect(server_private, limit: :infinity, binaries: :as_binaries)
    refute rendered =~ Base.encode16(mesh_key)
    refute rendered =~ inspect(mesh_key, limit: :infinity, binaries: :as_binaries)
  end
end
