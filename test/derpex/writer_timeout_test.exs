defmodule Derpex.WriterTimeoutTest do
  @moduledoc """
  The write timeout, per transport, against real listeners and real sockets.

  A client that stops reading must cost the server that one connection and
  nothing else. The mechanism differs underneath: `gen_tcp` enforces
  `send_timeout` in the driver; `:ssl.send` inherits it from the same option on
  the socket underneath the TLS sender (`tls_sender.erl`, the `{error, timeout}`
  clause of `send_or_buffer/5`, which OTP marks as retained for compatibility
  with the inet driver); and the WebSocket adapter rides whichever of the two it
  was upgraded from. All three are exercised here rather than assumed.
  """

  use ExUnit.Case, async: false

  alias Derpex.Certificates.Manual
  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Handshake
  alias Derpex.Listener.Handler
  alias Derpex.Secret

  @write_timeout_ms 200
  @stall_payload :binary.copy("x", 32 * 1_024)
  @flow_payload "still relaying"

  test "a stalled TCP client is closed while its neighbour keeps relaying" do
    assert_stalled_client_closed(:tcp)
  end

  test "a stalled TLS client is closed while its neighbour keeps relaying" do
    assert_stalled_client_closed(:tls)
  end

  test "a stalled WebSocket client is closed while its neighbour keeps relaying" do
    assert_stalled_client_closed(:websocket)
  end

  defp assert_stalled_client_closed(transport) do
    parent = self()

    event_handler = fn event ->
      send(parent, {:handler_event, self(), event})
      :ok
    end

    port = start_listener(transport, event_handler)

    # A small receive buffer means the server's writes back up quickly once
    # this client stops reading; it never reads at all.
    stalled = connect(transport, port, recbuf: 1_024, buffer: 1_024)
    stalled_handler = await_handler(stalled)

    flowing = connect(transport, port)
    _flowing_handler = await_handler(flowing)

    sender = connect(transport, port)
    _sender_handler = await_handler(sender)

    monitor = Process.monitor(stalled_handler)
    flood = start_flood(transport, sender, stalled.public_key, flowing.public_key)

    assert_receive {:DOWN, ^monitor, :process, ^stalled_handler, _reason},
                   @write_timeout_ms + 500

    # The neighbour was relaying while the stalled connection was timing out,
    # and still is now that it is gone.
    assert {:recv_packet, _source, @flow_payload} = recv_message(flowing)
    assert {:recv_packet, _source, @flow_payload} = recv_message(flowing)

    stop_flood(flood)
    close(stalled)
    close(flowing)
    close(sender)
  end

  defp start_listener(transport, event_handler) do
    {server_public_key, server_private_key} = Crypto.generate_keypair()

    server =
      start_supervised!(
        {ThousandIsland,
         [
           port: 0,
           num_acceptors: 3,
           handler_module: Handler,
           handler_options: [
             server_private_key: Secret.wrap(server_private_key),
             server_public_key: server_public_key,
             event_handler: event_handler
           ]
         ] ++ transport_options(transport)}
      )

    {:ok, {_address, port}} = ThousandIsland.listener_info(server)
    port
  end

  defp transport_options(:tls) do
    root =
      Path.join(System.tmp_dir!(), "derpex-writer-timeout-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(root) end)
    {:ok, certificate} = Manual.load_or_create(root, "127.0.0.1")

    [
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [
        ip: {127, 0, 0, 1},
        certfile: certificate.certificate_path,
        keyfile: certificate.key_path,
        send_timeout: @write_timeout_ms,
        send_timeout_close: true,
        sndbuf: 1_024
      ]
    ]
  end

  defp transport_options(_tcp_or_websocket) do
    [
      transport_options: [
        ip: {127, 0, 0, 1},
        send_timeout: @write_timeout_ms,
        send_timeout_close: true,
        # A floor, not a cap: the kernel enforces its own minimum.
        sndbuf: 1_024
      ]
    ]
  end

  defp connect(transport, port, socket_options \\ []) do
    client = open(transport, port, socket_options)
    :ok = send_data(client, upgrade_request(transport))
    :ok = read_upgrade_response(client)

    {:ok, :server_key, greeting} = recv_frame(client)
    {:ok, server_public_key} = Handshake.decode_server_key(greeting)
    {public_key, private_key} = Crypto.generate_keypair()
    info = %ClientInfo{version: 2, can_ack_pings: true, app_name: "writer-timeout"}
    {:ok, client_info} = Handshake.client_info_frame(private_key, server_public_key, info)
    :ok = send_frame(client, client_info)
    {:ok, :server_info, _payload} = recv_frame(client)

    Map.put(client, :public_key, public_key)
  end

  defp open(:tls, port, socket_options) do
    {:ok, socket} =
      :ssl.connect(
        {127, 0, 0, 1},
        port,
        [:binary, active: false, packet: :raw, verify: :verify_none] ++ socket_options,
        5_000
      )

    %{transport: :tls, socket: socket, buffer: <<>>}
  end

  defp open(transport, port, socket_options) do
    {:ok, socket} =
      :gen_tcp.connect(
        {127, 0, 0, 1},
        port,
        [:binary, active: false, packet: :raw, nodelay: true] ++ socket_options,
        5_000
      )

    %{transport: transport, socket: socket, buffer: <<>>}
  end

  defp upgrade_request(:websocket) do
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" <>
      "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: #{key}\r\n" <>
      "Sec-WebSocket-Protocol: derp\r\n\r\n"
  end

  defp upgrade_request(_native) do
    "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
  end

  defp read_upgrade_response(client, seen \\ "") do
    {:ok, data} = recv(client, 0)
    seen = seen <> data

    if String.contains?(seen, "\r\n\r\n") do
      [_headers, rest] = String.split(seen, "\r\n\r\n", parts: 2)
      put_buffer(client, rest)
      :ok
    else
      read_upgrade_response(client, seen)
    end
  end

  # The socket is passive and the client is a plain map, so the leftover bytes
  # of a read live in the process dictionary rather than in a threaded state.
  defp put_buffer(client, buffer), do: Process.put({:buffer, client.socket}, buffer)
  defp buffer(client), do: Process.get({:buffer, client.socket}, <<>>)

  defp send_frame(%{transport: :websocket} = client, frame) do
    send_data(client, websocket_client_frame(IO.iodata_to_binary(frame)))
  end

  defp send_frame(client, frame), do: send_data(client, frame)

  defp send_data(%{transport: :tls, socket: socket}, data), do: :ssl.send(socket, data)
  defp send_data(%{socket: socket}, data), do: :gen_tcp.send(socket, data)

  defp recv(%{transport: :tls, socket: socket}, length), do: :ssl.recv(socket, length, 5_000)
  defp recv(%{socket: socket}, length), do: :gen_tcp.recv(socket, length, 5_000)

  # One DERP frame, whatever it is wrapped in.
  defp recv_frame(%{transport: :websocket} = client) do
    <<type, length::unsigned-big-32, payload::binary-size(length)>> = websocket_message(client)
    {:ok, name} = Frame.type_name(type)
    {:ok, name, payload}
  end

  defp recv_frame(client) do
    <<type, length::unsigned-big-32>> = read_exactly(client, 5)
    {:ok, name} = Frame.type_name(type)
    {:ok, name, read_exactly(client, length)}
  end

  defp recv_message(client) do
    {:ok, type, payload} = recv_frame(client)
    {:ok, message} = Body.decode_server(Frame.type(type), payload)
    message
  end

  defp websocket_message(client) do
    <<0x82, first>> = read_exactly(client, 2)
    read_exactly(client, websocket_length(client, first))
  end

  defp websocket_length(client, 126) do
    <<length::unsigned-big-16>> = read_exactly(client, 2)
    length
  end

  defp websocket_length(client, 127) do
    <<length::unsigned-big-64>> = read_exactly(client, 8)
    length
  end

  defp websocket_length(_client, length), do: length

  defp read_exactly(client, length) do
    buffered = buffer(client)

    if byte_size(buffered) >= length do
      <<wanted::binary-size(^length), rest::binary>> = buffered
      put_buffer(client, rest)
      wanted
    else
      {:ok, data} = recv(client, 0)
      put_buffer(client, buffered <> data)
      read_exactly(client, length)
    end
  end

  defp websocket_client_frame(payload) do
    mask = :crypto.strong_rand_bytes(4)
    length = byte_size(payload)

    header =
      cond do
        length < 126 -> <<1::1, 0::3, 0x2::4, 1::1, length::7>>
        length <= 65_535 -> <<1::1, 0::3, 0x2::4, 1::1, 126::7, length::unsigned-big-16>>
        true -> <<1::1, 0::3, 0x2::4, 1::1, 127::7, length::unsigned-big-64>>
      end

    repeated = :binary.copy(mask, div(length + 3, 4))
    masked = :crypto.exor(binary_part(repeated, 0, length), payload)
    header <> mask <> masked
  end

  defp await_handler(client) do
    key = client.public_key
    assert_receive {:handler_event, handler, {:authenticated, ^key, _info}}, 5_000
    handler
  end

  defp start_flood(transport, sender, stalled_key, flowing_key) do
    parent = self()

    spawn_link(fn ->
      send(parent, {:flooding, self()})
      flood(transport, sender, stalled_key, flowing_key)
    end)
    |> tap(fn flood -> assert_receive {:flooding, ^flood}, 1_000 end)
  end

  defp flood(transport, sender, stalled_key, flowing_key) do
    receive do
      :stop -> :ok
    after
      0 ->
        {:ok, stall} = Body.encode_client({:send_packet, stalled_key, @stall_payload})
        {:ok, flow} = Body.encode_client({:send_packet, flowing_key, @flow_payload})
        _ignored = send_frame(sender, stall)
        _ignored = send_frame(sender, flow)
        Process.sleep(1)
        flood(transport, sender, stalled_key, flowing_key)
    end
  end

  defp stop_flood(flood) do
    send(flood, :stop)
    :ok
  end

  defp close(%{transport: :tls, socket: socket}), do: :ssl.close(socket)
  defp close(%{socket: socket}), do: :gen_tcp.close(socket)
end
