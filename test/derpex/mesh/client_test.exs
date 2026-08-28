defmodule Derpex.Mesh.ClientTest do
  use ExUnit.Case, async: false

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Handshake
  alias Derpex.Mesh.Client
  alias Derpex.Router
  alias Derpex.ServerInfo

  test "watches, forwards, withdraws, and reconnects without a second hop" do
    parent = self()
    {server_public, server_private} = Crypto.generate_keypair()
    {local_public, local_private} = Crypto.generate_keypair()
    mesh_key = :binary.copy(<<0xA5>>, 32)
    remote_peer = :crypto.strong_rand_bytes(32)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, port}} = :inet.sockname(listener)

    fake =
      spawn(fn ->
        fake_server(listener, server_private, mesh_key, remote_peer, parent)
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(fake), do: Process.exit(fake, :kill)
    end)

    event_handler = fn event ->
      send(parent, {:mesh_event, event})
      :ok
    end

    client =
      start_supervised!(
        {Client,
         url: "http://mesh.example.test:#{port}/derp",
         dial_host: "127.0.0.1",
         private_key: local_private,
         mesh_key: mesh_key,
         reconnect_interval: 25,
         event_handler: event_handler}
      )

    assert_receive {:fake_authenticated, 1, ^local_public,
                    %ClientInfo{mesh_key: ^mesh_key, can_ack_pings: true}},
                   2_000

    assert_receive {:mesh_event, {:peer_present, ^remote_peer}}, 2_000
    assert_receive {:mesh_event, {:connected, ^server_public}}, 2_000
    assert_receive {:fake_pong, 1, "12345678"}, 2_000

    source = :crypto.strong_rand_bytes(32)
    assert Router.route(source, remote_peer, "first hop") in [{:ok, :wake}, {:ok, :coalesced}]
    assert_receive {:fake_forward, 1, ^source, ^remote_peer, "first hop"}, 2_000

    send(fake, :close_first)
    assert_receive {:mesh_event, {:disconnected, :closed}}, 2_000

    assert Router.route(source, remote_peer, "withdrawn") ==
             {:dropped, :unknown_destination}

    assert_receive {:fake_authenticated, 2, ^local_public, %ClientInfo{mesh_key: ^mesh_key}},
                   2_000

    assert_receive {:mesh_event, {:peer_present, ^remote_peer}}, 2_000
    assert_receive {:mesh_event, {:connected, _server_public}}, 2_000

    assert Router.route(source, remote_peer, "after reconnect") in [
             {:ok, :wake},
             {:ok, :coalesced}
           ]

    assert_receive {:fake_forward, 2, ^source, ^remote_peer, "after reconnect"}, 2_000

    send(fake, :send_gone)
    assert_receive {:mesh_event, {:peer_gone, ^remote_peer, 0x00}}, 2_000

    assert Router.route(source, remote_peer, "gone") ==
             {:dropped, :unknown_destination}

    assert %{connected?: true, remote_peer_count: 0, disabled?: false} =
             Client.status(client)
  end

  test "detects a connection to its own server identity and stays disabled" do
    parent = self()
    {local_public, local_private} = Crypto.generate_keypair()
    mesh_key = :binary.copy(<<7>>, 32)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, port}} = :inet.sockname(listener)

    fake =
      spawn(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {:ok, _request, read_ahead} = receive_http_head(socket, "")
        {:ok, server_key} = Handshake.server_key_frame(local_private)

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
            server_key
          ])

        send(parent, {:self_server_read_ahead, read_ahead})
        Process.sleep(250)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(fake), do: Process.exit(fake, :kill)
    end)

    client =
      start_supervised!(
        {Client,
         url: "http://127.0.0.1:#{port}/derp",
         private_key: local_private,
         mesh_key: mesh_key,
         reconnect_interval: 10,
         event_handler: fn event -> send(parent, {:self_event, event}) end}
      )

    assert_receive {:self_server_read_ahead, ""}, 2_000
    assert_receive {:self_event, {:self_connect, ^local_public}}, 2_000

    assert %{
             connected?: false,
             disabled?: true,
             remote_server_key: ^local_public,
             remote_peer_count: 0
           } = Client.status(client)

    refute_receive {:self_event, {:connected, _key}}, 100
  end

  test "reports an initial dial failure before scheduling a retry" do
    parent = self()
    {_public_key, private_key} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, unavailable_port}} = :inet.sockname(listener)
    :gen_tcp.close(listener)

    client =
      start_supervised!(
        {Client,
         url: "http://127.0.0.1:#{unavailable_port}/derp",
         private_key: private_key,
         mesh_key: mesh_key,
         connect_timeout: 250,
         reconnect_interval: 60_000,
         event_handler: fn event -> send(parent, {:dial_event, event}) end}
      )

    assert_receive {:dial_event, {:connect_error, {:connect, reason}}}, 2_000
    assert reason in [:econnrefused, :timeout]
    assert %{connected?: false, last_error: {:connect, ^reason}} = Client.status(client)
  end

  defp fake_server(listener, server_private, mesh_key, remote_peer, parent) do
    fake_generation(listener, server_private, mesh_key, remote_peer, parent, 1)
    fake_generation(listener, server_private, mesh_key, remote_peer, parent, 2)
  rescue
    error -> send(parent, {:fake_error, error, __STACKTRACE__})
  end

  defp fake_generation(listener, server_private, mesh_key, remote_peer, parent, generation) do
    {:ok, socket} = :gen_tcp.accept(listener)
    {:ok, request, read_ahead} = receive_http_head(socket, "")
    true = request =~ "\r\nHost: mesh.example.test:"
    {:ok, server_key} = Handshake.server_key_frame(server_private)

    :ok =
      :gen_tcp.send(socket, [
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
        server_key
      ])

    {:ok, client_type, client_body, read_ahead} = receive_frame(socket, read_ahead)
    true = client_type == Frame.type(:client_info)
    {:ok, client_public, client_info} = Handshake.decode_client_info(client_body, server_private)
    true = client_info.mesh_key == mesh_key

    {:ok, watch_type, watch_body, read_ahead} = receive_frame(socket, read_ahead)
    true = watch_type == Frame.type(:watch_connections)
    {:ok, :watch_connections} = Body.decode_client(watch_type, watch_body)
    true = read_ahead == ""

    {:ok, server_info} =
      Handshake.server_info_frame(server_private, client_public, %ServerInfo{version: 2})

    {:ok, peer_present} =
      Body.encode_server({:peer_present, remote_peer, <<0::128>>, 12_345, 0x01, "remote"})

    {:ok, ping} = Body.encode_server({:ping, "12345678"})
    :ok = :gen_tcp.send(socket, [server_info, peer_present, ping])
    send(parent, {:fake_authenticated, generation, client_public, client_info})

    {source, destination, packet} = receive_forward(socket, "", generation, parent)
    send(parent, {:fake_forward, generation, source, destination, packet})

    case generation do
      1 ->
        receive do
          :close_first -> :gen_tcp.close(socket)
        end

      2 ->
        receive do
          :send_gone ->
            {:ok, peer_gone} = Body.encode_server({:peer_gone, remote_peer, 0x00})
            :ok = :gen_tcp.send(socket, peer_gone)
        end

        receive do
          :stop -> :gen_tcp.close(socket)
        end
    end
  end

  defp receive_forward(socket, buffer, generation, parent) do
    {:ok, type, body, rest} = receive_frame(socket, buffer)

    if type == Frame.type(:pong) do
      send(parent, {:fake_pong, generation, body})
      receive_forward(socket, rest, generation, parent)
    else
      {:ok, {:forward_packet, source, destination, packet}} =
        Body.decode_client(type, body)

      {source, destination, packet}
    end
  end

  defp receive_http_head(socket, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} ->
        <<request::binary-size(^head_length), "\r\n\r\n", read_ahead::binary>> = buffer
        {:ok, request, read_ahead}

      :nomatch ->
        with {:ok, data} <- :gen_tcp.recv(socket, 0, 2_000) do
          receive_http_head(socket, buffer <> data)
        end
    end
  end

  defp receive_frame(socket, buffer) do
    with {:ok, buffer} <- ensure_bytes(socket, buffer, 5),
         {:ok, type, length, _rest} <- Frame.decode_header(buffer),
         {:ok, buffer} <- ensure_bytes(socket, buffer, 5 + length) do
      <<_header::binary-size(5), body::binary-size(^length), rest::binary>> = buffer
      {:ok, type, body, rest}
    end
  end

  defp ensure_bytes(_socket, buffer, wanted) when byte_size(buffer) >= wanted,
    do: {:ok, buffer}

  defp ensure_bytes(socket, buffer, wanted) do
    with {:ok, data} <- :gen_tcp.recv(socket, 0, 2_000) do
      ensure_bytes(socket, buffer <> data, wanted)
    end
  end
end
