defmodule Derpex.Mesh.ClientTest do
  use ExUnit.Case, async: false

  alias Derpex.Certificates.Manual
  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Handshake
  alias Derpex.Mesh.Client
  alias Derpex.Router
  alias Derpex.Secret
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
         private_key: Secret.wrap(local_private),
         mesh_key: Secret.wrap(mesh_key),
         reconnect_interval: 25,
         event_handler: event_handler}
      )

    assert_receive {:fake_authenticated, 1, ^local_public,
                    %ClientInfo{mesh_key: ^mesh_key, can_ack_pings: true}},
                   2_000

    assert_receive {:mesh_event, {:peer_present, ^remote_peer}}, 2_000
    assert_receive {:mesh_event, {:connected, ^server_public}}, 2_000
    assert_receive {:fake_pong, 1, "12345678"}, 2_000

    assert {:ok, {{127, 0, 0, 1}, local_port}} = Client.local_address(client)
    assert local_port in 1..65_535

    :ok = :sys.suspend(client)

    try do
      started_at = System.monotonic_time()
      assert Client.local_address(client) == {:ok, {{127, 0, 0, 1}, local_port}}

      assert System.monotonic_time() - started_at <
               System.convert_time_unit(100, :millisecond, :native)
    after
      :ok = :sys.resume(client)
    end

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
         private_key: Secret.wrap(local_private),
         mesh_key: Secret.wrap(mesh_key),
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
         private_key: Secret.wrap(private_key),
         mesh_key: Secret.wrap(mesh_key),
         connect_timeout: 250,
         reconnect_interval: 60_000,
         event_handler: fn event -> send(parent, {:dial_event, event}) end}
      )

    assert_receive {:dial_event, {:connect_error, {:connect, reason}}}, 2_000
    assert reason in [:econnrefused, :timeout]
    assert %{connected?: false, last_error: {:connect, ^reason}} = Client.status(client)
    assert Client.local_address(client) == {:error, :not_connected}
  end

  test "CONNECT proxy targets the configured non-default DERP port" do
    parent = self()
    {_server_public, server_private} = Crypto.generate_keypair()
    {_local_public, local_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, derp_listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, derp_port}} = :inet.sockname(derp_listener)

    derp_server =
      spawn(fn ->
        fake_proxy_derp_server(derp_listener, server_private, mesh_key, parent)
      end)

    {:ok, proxy_listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, proxy_port}} = :inet.sockname(proxy_listener)
    proxy = spawn(fn -> fake_connect_proxy(proxy_listener, parent) end)

    on_exit(fn ->
      :gen_tcp.close(derp_listener)
      :gen_tcp.close(proxy_listener)
      if Process.alive?(derp_server), do: Process.exit(derp_server, :kill)
      if Process.alive?(proxy), do: Process.exit(proxy, :kill)
    end)

    client =
      start_supervised!(
        {Client,
         url: "http://127.0.0.1:#{derp_port}/derp",
         proxy_url: "http://127.0.0.1:#{proxy_port}",
         private_key: Secret.wrap(local_private),
         mesh_key: Secret.wrap(mesh_key),
         reconnect_interval: 60_000}
      )

    expected_target = "127.0.0.1:#{derp_port}"
    assert_receive {:proxy_target, ^expected_target}, 2_000
    assert_receive :proxy_derp_authenticated, 2_000
    assert %{connected?: true} = Client.status(client)
  end

  test "a peer that stops reading trips the send timeout and reconnects" do
    parent = self()
    {_server_public, server_private} = Crypto.generate_keypair()
    {_local_public, local_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)
    remote_peer = :crypto.strong_rand_bytes(32)

    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        recbuf: 1_024,
        buffer: 1_024
      ])

    {:ok, {_ip, port}} = :inet.sockname(listener)

    fake =
      spawn(fn -> stalled_server(listener, server_private, mesh_key, remote_peer, parent) end)

    on_exit(fn ->
      :gen_tcp.close(listener)
      if Process.alive?(fake), do: Process.exit(fake, :kill)
    end)

    _client =
      start_supervised!(
        {Client,
         url: "http://127.0.0.1:#{port}/derp",
         private_key: Secret.wrap(local_private),
         mesh_key: Secret.wrap(mesh_key),
         send_timeout: 200,
         reconnect_interval: 25,
         queue_capacity: 64,
         event_handler: fn event -> send(parent, {:mesh_event, event}) end}
      )

    assert_receive {:stalled_authenticated, 1}, 2_000
    assert_receive {:mesh_event, {:peer_present, ^remote_peer}}, 2_000

    source = :crypto.strong_rand_bytes(32)
    packet = :binary.copy(<<0xAB>>, 60_000)
    Enum.each(1..64, fn _index -> Router.route(source, remote_peer, packet) end)

    assert_receive {:mesh_event, {:disconnected, :timeout}}, 6_000
    assert_receive {:stalled_authenticated, 2}, 6_000
  end

  test "a stalled TLS peer trips the send timeout under TLS and reconnects" do
    parent = self()
    {_server_public, server_private} = Crypto.generate_keypair()
    {_local_public, local_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)
    remote_peer = :crypto.strong_rand_bytes(32)

    directory =
      Path.join(System.tmp_dir!(), "derpex-mesh-tls-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")

    listen_options =
      Manual.tls_options(manual) ++
        [
          :binary,
          packet: :raw,
          active: false,
          reuseaddr: true,
          recbuf: 1_024,
          buffer: 1_024,
          versions: [:"tlsv1.3"]
        ]

    {:ok, listener} = :ssl.listen(0, listen_options)
    {:ok, {_ip, port}} = :ssl.sockname(listener)

    fake =
      spawn(fn -> stalled_tls_server(listener, server_private, mesh_key, remote_peer, parent) end)

    on_exit(fn ->
      :ssl.close(listener)
      if Process.alive?(fake), do: Process.exit(fake, :kill)
    end)

    _client =
      start_supervised!(
        {Client,
         url: "https://127.0.0.1:#{port}/derp",
         private_key: Secret.wrap(local_private),
         mesh_key: Secret.wrap(mesh_key),
         tls_options: [verify: :verify_none, cacerts: []],
         send_timeout: 300,
         reconnect_interval: 25,
         queue_capacity: 64,
         event_handler: fn event -> send(parent, {:mesh_event, event}) end}
      )

    assert_receive {:stalled_authenticated, 1}, 5_000
    assert_receive {:mesh_event, {:peer_present, ^remote_peer}}, 5_000

    source = :crypto.strong_rand_bytes(32)
    packet = :binary.copy(<<0xCD>>, 60_000)
    Enum.each(1..64, fn _index -> Router.route(source, remote_peer, packet) end)

    assert_receive {:mesh_event, {:disconnected, :timeout}}, 6_000
    assert_receive {:stalled_authenticated, 2}, 6_000
  end

  defp stalled_tls_server(listener, server_private, mesh_key, remote_peer, parent) do
    Enum.each(1..2, fn generation ->
      {:ok, pending} = :ssl.transport_accept(listener)
      {:ok, socket} = :ssl.handshake(pending, 5_000)
      _read_ahead = mesh_handshake({:ssl, socket}, server_private, mesh_key, remote_peer)
      send(parent, {:stalled_authenticated, generation})
    end)

    receive do
      :stop -> :ok
    end
  rescue
    error -> send(parent, {:fake_error, error, __STACKTRACE__})
  end

  defp stalled_server(listener, server_private, mesh_key, remote_peer, parent) do
    Enum.each(1..2, fn generation ->
      {:ok, socket} = :gen_tcp.accept(listener)
      _read_ahead = mesh_handshake(socket, server_private, mesh_key, remote_peer)
      send(parent, {:stalled_authenticated, generation})
    end)

    receive do
      :stop -> :ok
    end
  rescue
    error -> send(parent, {:fake_error, error, __STACKTRACE__})
  end

  defp mesh_handshake(socket, server_private, mesh_key, remote_peer) do
    {:ok, _request, read_ahead} = receive_http_head(socket, "")
    {:ok, server_key} = Handshake.server_key_frame(server_private)

    :ok =
      transport_send(socket, [
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

    {:ok, server_info} =
      Handshake.server_info_frame(server_private, client_public, %ServerInfo{version: 2})

    {:ok, peer_present} =
      Body.encode_server({:peer_present, remote_peer, <<0::128>>, 12_345, 0x01, "remote"})

    :ok = transport_send(socket, [server_info, peer_present])
    read_ahead
  end

  defp fake_server(listener, server_private, mesh_key, remote_peer, parent) do
    fake_generation(listener, server_private, mesh_key, remote_peer, parent, 1)
    fake_generation(listener, server_private, mesh_key, remote_peer, parent, 2)
  rescue
    error -> send(parent, {:fake_error, error, __STACKTRACE__})
  end

  defp fake_proxy_derp_server(listener, server_private, mesh_key, parent) do
    {:ok, socket} = :gen_tcp.accept(listener)
    {:ok, _request, read_ahead} = receive_http_head(socket, "")
    {:ok, server_key} = Handshake.server_key_frame(server_private)

    :ok =
      :gen_tcp.send(socket, [
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
        server_key
      ])

    {:ok, client_type, client_body, read_ahead} = receive_frame(socket, read_ahead)
    true = client_type == Frame.type(:client_info)

    {:ok, client_public, %ClientInfo{mesh_key: ^mesh_key}} =
      Handshake.decode_client_info(client_body, server_private)

    {:ok, watch_type, watch_body, ""} = receive_frame(socket, read_ahead)
    {:ok, :watch_connections} = Body.decode_client(watch_type, watch_body)

    {:ok, server_info} =
      Handshake.server_info_frame(server_private, client_public, %ServerInfo{version: 2})

    :ok = :gen_tcp.send(socket, server_info)
    send(parent, :proxy_derp_authenticated)

    receive do
      :stop -> :gen_tcp.close(socket)
    end
  rescue
    error -> send(parent, {:proxy_derp_error, error, __STACKTRACE__})
  end

  defp fake_connect_proxy(listener, parent) do
    {:ok, client} = :gen_tcp.accept(listener)
    {:ok, request, read_ahead} = receive_http_head(client, "")
    [request_line | _headers] = :binary.split(request, "\r\n", [:global])
    ["CONNECT", target, _version] = :binary.split(request_line, " ", [:global])
    send(parent, {:proxy_target, target})

    uri = URI.parse("http://#{target}")

    {:ok, upstream} =
      :gen_tcp.connect(String.to_charlist(uri.host), uri.port, [
        :binary,
        packet: :raw,
        active: false
      ])

    :ok = :gen_tcp.send(client, "HTTP/1.1 200 OK\r\n\r\n")
    if read_ahead != "", do: :ok = :gen_tcp.send(upstream, read_ahead)
    proxy_relay(client, upstream)
  rescue
    error -> send(parent, {:proxy_error, error, __STACKTRACE__})
  end

  defp proxy_relay(client, upstream) do
    :ok = :inet.setopts(client, active: :once)
    :ok = :inet.setopts(upstream, active: :once)
    proxy_relay_loop(client, upstream)
  end

  defp proxy_relay_loop(client, upstream) do
    receive do
      {:tcp, ^client, data} ->
        :ok = :gen_tcp.send(upstream, data)
        :ok = :inet.setopts(client, active: :once)
        proxy_relay_loop(client, upstream)

      {:tcp, ^upstream, data} ->
        :ok = :gen_tcp.send(client, data)
        :ok = :inet.setopts(upstream, active: :once)
        proxy_relay_loop(client, upstream)

      {:tcp_closed, socket} when socket in [client, upstream] ->
        :gen_tcp.close(client)
        :gen_tcp.close(upstream)
    end
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
        with {:ok, data} <- transport_recv(socket) do
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
    with {:ok, data} <- transport_recv(socket) do
      ensure_bytes(socket, buffer <> data, wanted)
    end
  end

  defp transport_recv({:ssl, socket}), do: :ssl.recv(socket, 0, 2_000)
  defp transport_recv(socket), do: :gen_tcp.recv(socket, 0, 2_000)

  defp transport_send({:ssl, socket}, data), do: :ssl.send(socket, data)
  defp transport_send(socket, data), do: :gen_tcp.send(socket, data)
end
