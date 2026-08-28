defmodule Derpex.Listener.HandlerTest do
  use ExUnit.Case, async: false

  alias Derpex.AcceptLimiter
  alias Derpex.ClientInfo
  alias Derpex.Clock.Manual
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake
  alias Derpex.Listener.Handler
  alias Derpex.Outbox.Ring
  alias Derpex.RateConfig
  alias Derpex.RateController

  test "official-style cleartext HTTP client completes an authenticated handshake" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    parent = self()

    event_handler = fn event ->
      send(parent, event)
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private, event_handler: event_handler]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])

    request =
      "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"

    :ok = :gen_tcp.send(socket, request)

    expected_response =
      "HTTP/1.1 101 Switching Protocols\r\n" <>
        "Upgrade: DERP\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Derp-Version: 2\r\n" <>
        "Derp-Public-Key: #{Base.encode16(server_public, case: :lower)}\r\n\r\n"

    assert {:ok, ^expected_response} = :gen_tcp.recv(socket, byte_size(expected_response), 2_000)
    assert {:ok, <<type, 40::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert type == Frame.type(:server_key)
    assert {:ok, greeting} = :gen_tcp.recv(socket, 40, 2_000)
    assert Handshake.decode_server_key(greeting) == {:ok, server_public}

    client_info = %ClientInfo{version: 2, can_ack_pings: true, app_name: "socket-test"}
    {:ok, client_frame} = Handshake.client_info_frame(client_private, server_public, client_info)
    :ok = :gen_tcp.send(socket, client_frame)

    assert_receive {:authenticated, ^client_public, ^client_info}, 2_000
    assert {:ok, <<server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert server_info_type == Frame.type(:server_info)
    assert {:ok, server_info_body} = :gen_tcp.recv(socket, length, 2_000)

    assert Handshake.decode_server_info(server_info_body, client_private, server_public) ==
             {:ok, %Derpex.ServerInfo{version: 2}}

    :gen_tcp.close(socket)
  end

  test "pipelined fast start begins directly with DERP and preserves client info" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    parent = self()

    event_handler = fn event ->
      send(parent, event)
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private, event_handler: event_handler]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])

    request =
      "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Fast-Start: 1\r\n\r\n"

    client_info = %ClientInfo{version: 2}
    {:ok, client_frame} = Handshake.client_info_frame(client_private, server_public, client_info)
    :ok = :gen_tcp.send(socket, [request, client_frame])

    assert {:ok, <<type, 40::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert type == Frame.type(:server_key)
    assert {:ok, _greeting} = :gen_tcp.recv(socket, 40, 2_000)
    assert_receive {:authenticated, ^client_public, ^client_info}, 2_000
    assert {:ok, <<server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert server_info_type == Frame.type(:server_info)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)
    :gen_tcp.close(socket)
  end

  test "admission runs before registration while trusted mesh peers bypass it" do
    {server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :binary.copy(<<7>>, 32)
    parent = self()

    admission = fn request ->
      send(parent, {:admission_called, request.node_key})
      {:error, :policy_denied}
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: server_private,
          mesh_key: mesh_key,
          admission: admission,
          disallowed_app_names: ["badapp"]
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    {bad_public, bad_private} = Crypto.generate_keypair()

    bad_socket =
      connect_and_send_info(port, server_public, bad_private, %ClientInfo{app_name: "badapp"})

    assert {:error, :closed} = :gen_tcp.recv(bad_socket, 0, 2_000)
    refute_receive {:admission_called, ^bad_public}

    {denied_public, denied_private} = Crypto.generate_keypair()
    denied_socket = connect_and_send_info(port, server_public, denied_private, %ClientInfo{})
    assert_receive {:admission_called, ^denied_public}, 2_000
    assert {:error, :closed} = :gen_tcp.recv(denied_socket, 0, 2_000)

    {mesh_public, mesh_private} = Crypto.generate_keypair()

    mesh_socket =
      connect_and_send_info(port, server_public, mesh_private, %ClientInfo{
        app_name: "badapp",
        mesh_key: mesh_key
      })

    assert {:ok, <<server_info_type, length::unsigned-big-32>>} =
             :gen_tcp.recv(mesh_socket, 5, 2_000)

    assert server_info_type == Frame.type(:server_info)
    assert {:ok, _server_info_body} = :gen_tcp.recv(mesh_socket, length, 2_000)
    refute_receive {:admission_called, ^mesh_public}

    :gen_tcp.close(bad_socket)
    :gen_tcp.close(denied_socket)
    :gen_tcp.close(mesh_socket)
  end

  test "receive-byte limiting paces frame handling and leaves the socket under backpressure" do
    start_supervised!({Manual, monotonic_time: 0})
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)

    minimum = RateConfig.minimum_burst()

    rate_controller =
      start_supervised!(
        {RateController,
         name: nil,
         config: %RateConfig{
           per_client_rate_limit_bytes_per_second: minimum,
           per_client_rate_burst_bytes: minimum
         }}
      )

    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()
    destination = :crypto.strong_rand_bytes(32)
    payload = :binary.copy(<<0xA5>>, 65_536)
    parent = self()

    event_handler = fn event ->
      send(parent, {:handler_event, self(), event})
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: server_private,
          event_handler: event_handler,
          rate_controller: rate_controller
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})
    assert_receive {:handler_event, handler, {:authenticated, _key, %ClientInfo{}}}, 2_000
    assert {:ok, <<server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert server_info_type == Frame.type(:server_info)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)

    packet = IO.iodata_to_binary(Frame.encode(:send_packet, [destination, payload]))
    :ok = :gen_tcp.send(socket, packet)

    assert_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   2_000

    :ok = :gen_tcp.send(socket, packet)

    refute_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   25

    assert_eventually(fn -> Manual.pending_timer_count() == 2 end)

    :ok = Manual.advance(999)

    refute_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   25

    :ok = Manual.advance(1)

    assert_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   2_000

    :ok = :gen_tcp.send(socket, packet)
    assert_eventually(fn -> Manual.pending_timer_count() == 2 end)
    monitor = Process.monitor(handler)
    Process.unlink(server)
    Process.exit(server, :shutdown)
    assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 2_000
    :gen_tcp.close(socket)
  end

  test "accept limiting closes excess sockets before HTTP session allocation" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {0, 1}})
    {_server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [server_private_key: server_private, accept_limiter: limiter]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, admitted} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert {:error, :timeout} = :gen_tcp.recv(admitted, 0, 25)

    {:ok, rejected} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert {:error, :closed} = :gen_tcp.recv(rejected, 0, 2_000)
    :gen_tcp.close(admitted)
    :gen_tcp.close(rejected)
  end

  test "configured packet queue depth applies independently to ordinary and disco rings" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()
    parent = self()

    event_handler = fn event ->
      send(parent, {:queue_handler_event, self(), event})
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: server_private,
          send_queue_depth: 64,
          event_handler: event_handler
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})

    assert_receive {:queue_handler_event, handler, {:authenticated, _key, _info}}, 2_000
    {_thousand_island_socket, state} = :sys.get_state(handler)
    assert Ring.stats(state.ordinary).capacity == 64
    assert Ring.stats(state.disco).capacity == 64
    assert Ring.stats(state.lifecycle).capacity == 32
    assert Ring.stats(state.pong).capacity == 1
    :gen_tcp.close(socket)
  end

  defp stop_server_on_exit(server) do
    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)
    end)
  end

  defp connect_and_send_info(port, server_public, client_private, client_info) do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])

    request =
      "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"

    :ok = :gen_tcp.send(socket, request)

    expected_response =
      "HTTP/1.1 101 Switching Protocols\r\n" <>
        "Upgrade: DERP\r\n" <>
        "Connection: Upgrade\r\n" <>
        "Derp-Version: 2\r\n" <>
        "Derp-Public-Key: #{Base.encode16(server_public, case: :lower)}\r\n\r\n"

    assert {:ok, ^expected_response} =
             :gen_tcp.recv(socket, byte_size(expected_response), 2_000)

    assert {:ok, <<server_key_type, 40::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert server_key_type == Frame.type(:server_key)
    assert {:ok, _greeting} = :gen_tcp.recv(socket, 40, 2_000)

    {:ok, client_frame} = Handshake.client_info_frame(client_private, server_public, client_info)
    :ok = :gen_tcp.send(socket, client_frame)
    socket
  end

  defp assert_eventually(assertion, attempts \\ 50)

  defp assert_eventually(assertion, attempts) when attempts > 0 do
    if assertion.() do
      :ok
    else
      Process.sleep(2)
      assert_eventually(assertion, attempts - 1)
    end
  end

  defp assert_eventually(_assertion, 0), do: flunk("condition did not become true")
end
