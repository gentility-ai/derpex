defmodule Derpex.Listener.HandlerTest do
  use ExUnit.Case, async: false

  alias Derpex.AcceptLimiter
  alias Derpex.ClientInfo
  alias Derpex.Clock.Manual
  alias Derpex.Crypto
  alias Derpex.Drain
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Handshake
  alias Derpex.Listener.Handler
  alias Derpex.Metrics
  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Ring
  alias Derpex.RateConfig
  alias Derpex.RateController
  alias Derpex.Secret

  defmodule LifecyclePolicy do
    @behaviour Derpex.Admission

    @impl true
    def authorize(request, parent) do
      send(parent, {:authorized_connection, request.node_key, self()})
      {:ok, %{organization_id: "org_01"}}
    end

    @impl true
    def claim(request, context, connection, parent) do
      send(parent, {:claimed_connection, request.node_key, connection})
      {:ok, context}
    end

    @impl true
    def release(connection, parent) do
      send(parent, {:released_connection, connection})
      :ok
    end

    @impl true
    def reserve_bytes(context, bytes, parent) do
      send(parent, {:reserved_connection_bytes, context.organization_id, bytes, self()})
      {:ok, 0}
    end

    @impl true
    def record_usage(context, bytes, outcome, parent) do
      send(parent, {:recorded_connection_usage, context.organization_id, bytes, outcome, self()})
      :ok
    end
  end

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
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler
        ]
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
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler
        ]
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

    verifier = fn request ->
      send(parent, {:verifier_called, request.node_key})
      :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(mesh_key),
          client_verifier: verifier,
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
    refute_receive {:verifier_called, ^bad_public}
    refute_receive {:admission_called, ^bad_public}

    {denied_public, denied_private} = Crypto.generate_keypair()
    denied_socket = connect_and_send_info(port, server_public, denied_private, %ClientInfo{})
    assert_receive {:verifier_called, ^denied_public}, 2_000
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
    refute_receive {:verifier_called, ^mesh_public}
    refute_receive {:admission_called, ^mesh_public}

    :gen_tcp.close(bad_socket)
    :gen_tcp.close(denied_socket)
    :gen_tcp.close(mesh_socket)
  end

  test "connection-scoped admission claims are released when the socket closes" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          admission: {LifecyclePolicy, self()}
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{})

    assert_receive {:authorized_connection, ^client_public, handler}, 2_000
    assert_receive {:claimed_connection, ^client_public, ^handler}, 2_000
    assert {:ok, <<_server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)

    :ok = :gen_tcp.send(socket, Frame.encode(:ping, "pingpong"))
    assert_receive {:reserved_connection_bytes, "org_01", 8, ^handler}, 2_000
    pong_result = :gen_tcp.recv(socket, 13, 2_000)
    assert {:ok, <<pong_type, 8::unsigned-big-32, "pingpong">>} = pong_result
    assert pong_type == Frame.type(:pong)

    destination = :binary.copy(<<0xDD>>, 32)
    :ok = :gen_tcp.send(socket, Frame.encode(:send_packet, [destination, "data"]))
    assert_receive {:reserved_connection_bytes, "org_01", 36, ^handler}, 2_000
    assert_receive {:recorded_connection_usage, "org_01", 4, :dropped, ^handler}, 2_000

    :ok = :gen_tcp.close(socket)
    assert_receive {:released_connection, ^handler}, 2_000
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
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
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
    send(handler, {:derpex_admission_close, :quota_revision})
    assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 2_000
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
    :gen_tcp.close(socket)
  end

  test "a paced connection still keeps alive and still closes on demand" do
    start_supervised!({Manual, monotonic_time: 0})
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)

    # One byte per second, with the smallest burst the config allows: the first
    # frame is admitted from the burst, the second waits most of a day.
    rate_controller =
      start_supervised!(
        {RateController,
         name: nil,
         config: %RateConfig{
           per_client_rate_limit_bytes_per_second: 1,
           per_client_rate_burst_bytes: RateConfig.minimum_burst()
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
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler,
          rate_controller: rate_controller
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})
    assert_receive {:handler_event, handler, {:authenticated, _key, %ClientInfo{}}}, 2_000
    assert {:ok, <<_server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)

    packet = IO.iodata_to_binary(Frame.encode(:send_packet, [destination, payload]))
    :ok = :gen_tcp.send(socket, packet)

    assert_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   2_000

    :ok = :gen_tcp.send(socket, packet)
    assert_eventually(fn -> Manual.pending_timer_count() == 2 end)

    # The keepalive is due long before the pace is: a handler that parked in a
    # selective receive would answer neither.
    :ok = Manual.advance(65_000)
    assert {:ok, <<keep_alive_type, 0::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert keep_alive_type == Frame.type(:keep_alive)

    monitor = Process.monitor(handler)
    send(handler, {:derpex_drain_close, make_ref()})
    assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 100
    :gen_tcp.close(socket)
  end

  test "a paced WebSocket connection is paced, not crashed" do
    start_supervised!({Manual, monotonic_time: 0})
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)

    rate_controller =
      start_supervised!(
        {RateController,
         name: nil,
         config: %RateConfig{
           per_client_rate_limit_bytes_per_second: 1,
           per_client_rate_burst_bytes: RateConfig.minimum_burst()
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
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler,
          rate_controller: rate_controller
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_websocket(port, server_public, client_private)
    assert_receive {:handler_event, handler, {:authenticated, _key, %ClientInfo{}}}, 2_000
    monitor = Process.monitor(handler)

    packet = IO.iodata_to_binary(Frame.encode(:send_packet, [destination, payload]))
    :ok = :gen_tcp.send(socket, websocket_client_frame(packet))

    assert_receive {:handler_event, ^handler,
                    {:client_message, {:send_packet, ^destination, ^payload}}},
                   2_000

    # The second message is the one that pauses: it is a rate-limit decision
    # the WebSocket path used to have no branch for, and the connection died of
    # a CaseClauseError instead of waiting.
    :ok = :gen_tcp.send(socket, websocket_client_frame(packet))
    assert_eventually(fn -> Manual.pending_timer_count() == 2 end)
    refute_received {:DOWN, ^monitor, :process, ^handler, _reason}

    # Paced, and still answering: a drain close closes it without the clock
    # ever reaching the pace deadline.
    send(handler, {:derpex_drain_close, make_ref()})
    assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 100
    :gen_tcp.close(socket)
  end

  defp connect_websocket(port, server_public, client_private) do
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    request =
      "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" <>
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: #{key}\r\n" <>
        "Sec-WebSocket-Protocol: derp\r\n\r\n"

    :ok = :gen_tcp.send(socket, request)
    :ok = read_until_blank_line(socket)

    {:ok, :server_key, greeting} = recv_websocket_frame(socket)
    {:ok, ^server_public} = Handshake.decode_server_key(greeting)

    info = %ClientInfo{version: 2, can_ack_pings: true, app_name: "ws-pacing"}
    {:ok, client_info} = Handshake.client_info_frame(client_private, server_public, info)
    :ok = :gen_tcp.send(socket, websocket_client_frame(IO.iodata_to_binary(client_info)))
    {:ok, :server_info, _payload} = recv_websocket_frame(socket)
    socket
  end

  defp read_until_blank_line(socket, seen \\ "") do
    {:ok, data} = :gen_tcp.recv(socket, 0, 2_000)
    seen = seen <> data

    if String.contains?(seen, "\r\n\r\n") do
      [_headers, rest] = String.split(seen, "\r\n\r\n", parts: 2)
      Process.put({:ws_buffer, socket}, rest)
      :ok
    else
      read_until_blank_line(socket, seen)
    end
  end

  defp recv_websocket_frame(socket) do
    <<0x82, first>> = read_exactly(socket, 2)

    length =
      case first do
        126 -> :binary.decode_unsigned(read_exactly(socket, 2))
        127 -> :binary.decode_unsigned(read_exactly(socket, 8))
        length -> length
      end

    <<type, frame_length::unsigned-big-32, payload::binary-size(frame_length)>> =
      read_exactly(socket, length)

    {:ok, name} = Frame.type_name(type)
    {:ok, name, payload}
  end

  defp read_exactly(socket, length) do
    buffered = Process.get({:ws_buffer, socket}, "")

    if byte_size(buffered) >= length do
      <<wanted::binary-size(^length), rest::binary>> = buffered
      Process.put({:ws_buffer, socket}, rest)
      wanted
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2_000)
      Process.put({:ws_buffer, socket}, buffered <> data)
      read_exactly(socket, length)
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
    header <> mask <> :crypto.exor(binary_part(repeated, 0, length), payload)
  end

  test "a crashing mesh connection does not print the peer's mesh key" do
    {server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)
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
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          mesh_key: Secret.wrap(mesh_key),
          event_handler: event_handler
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {_mesh_public, mesh_private} = Crypto.generate_keypair()

    socket =
      connect_and_send_info(port, server_public, mesh_private, %ClientInfo{
        version: 2,
        mesh_key: mesh_key
      })

    assert_receive {:handler_event, handler, {:authenticated, _key, %ClientInfo{}}}, 2_000
    monitor = Process.monitor(handler)

    # An unmatched message crashes the handler, and a crash report prints the
    # process state - which holds the peer's ClientInfo.
    log =
      ExUnit.CaptureLog.capture_log(fn ->
        send(handler, :derpex_unmatched_message)
        assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 2_000
      end)

    assert log =~ "terminating"
    refute log =~ Base.encode16(mesh_key)
    refute log =~ Base.encode16(mesh_key, case: :lower)
    refute log =~ inspect(mesh_key, limit: :infinity, binaries: :as_binaries)
    :gen_tcp.close(socket)
  end

  test "accept limiting closes excess sockets before HTTP session allocation" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {0, 1}})
    {server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          accept_limiter: limiter
        ]
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

  test "per-IP connection claims are released when an unauthenticated socket closes" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip_connections: 1, max_tracked_ips: 16]}
      )

    {server_public, server_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          accept_limiter: limiter
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, first} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert_eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 1 end)

    {:ok, rejected} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert {:error, :closed} = :gen_tcp.recv(rejected, 0, 2_000)
    :gen_tcp.close(rejected)

    :gen_tcp.close(first)
    assert_eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 0 end)

    {:ok, replacement} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    assert_eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 1 end)
    assert {:error, :timeout} = :gen_tcp.recv(replacement, 0, 25)
    :gen_tcp.close(replacement)
  end

  test "Gentility drain sends restarting to a home client and enforces its deadline" do
    drain =
      start_supervised!({Drain, name: nil, profile: :gentility, jitter: fn _maximum -> 0 end})

    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          drain: drain
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})

    assert {:ok, <<server_info_type, server_info_length::unsigned-big-32>>} =
             :gen_tcp.recv(socket, 5, 2_000)

    assert server_info_type == Frame.type(:server_info)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, server_info_length, 2_000)

    {:ok, preferred_frame} = Body.encode_client({:note_preferred, true})
    :ok = :gen_tcp.send(socket, preferred_frame)
    assert_eventually(fn -> Drain.stats(drain).home_connections == 1 end)

    assert {:ok, %{targeted_connections: 1}} =
             Drain.begin_drain(drain,
               reconnect_ms: 250,
               try_for_ms: 2_000,
               jitter_ms: 100,
               deadline_ms: 100
             )

    assert {:ok, <<restarting_type, 8::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert restarting_type == Frame.type(:restarting)

    assert {:ok, <<250::unsigned-big-32, 2_000::unsigned-big-32>>} =
             :gen_tcp.recv(socket, 8, 2_000)

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
    assert_eventually(fn -> Drain.stats(drain).connections == 0 end)
    :gen_tcp.close(socket)
  end

  test "authenticated control flow updates fixed counters outside the writer mailbox" do
    before = Metrics.snapshot()
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})

    assert {:ok, <<server_info_type, server_info_length::unsigned-big-32>>} =
             :gen_tcp.recv(socket, 5, 2_000)

    assert server_info_type == Frame.type(:server_info)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, server_info_length, 2_000)

    {:ok, ping_frame} = Body.encode_client({:ping, "12345678"})
    :ok = :gen_tcp.send(socket, ping_frame)

    assert {:ok, <<pong_type, 8::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert pong_type == Frame.type(:pong)
    assert {:ok, "12345678"} = :gen_tcp.recv(socket, 8, 2_000)

    {:ok, packet_frame} =
      Body.encode_client({:send_packet, :binary.copy(<<9>>, 32), "unroutable"})

    :ok = :gen_tcp.send(socket, packet_frame)

    assert_eventually(fn ->
      current = Metrics.snapshot()

      current.accepts == before.accepts + 1 and
        current.got_ping == before.got_ping + 1 and
        current.sent_pong == before.sent_pong + 1 and
        current.packets_received == before.packets_received + 1 and
        current.bytes_received == before.bytes_received + byte_size("unroutable") and
        current[{:packets_dropped, :unknown_dest, :other}] ==
          before[{:packets_dropped, :unknown_dest, :other}] + 1
    end)

    :gen_tcp.close(socket)
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
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
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
    # Lifecycle frames are state changes, so their queue grows instead of
    # replacing: it has a soft cap, not a capacity.
    assert LifecycleQueue.stats(state.lifecycle).soft_cap == 65_536
    assert Ring.stats(state.pong).capacity == 1
    :gen_tcp.close(socket)
  end

  test "serves authorized traffic diagnostics as a live chunked stream" do
    {server_public, server_private} = Crypto.generate_keypair()
    parent = self()

    run_ss = fn ->
      send(parent, :traffic_sampled)
      {:ok, ""}
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          debug: [traffic: [run_ss: run_ss, interval_ms: 60_000]]
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    :ok = :gen_tcp.send(socket, "GET /debug/traffic HTTP/1.1\r\nHost: localhost\r\n\r\n")

    assert {:ok, response} = recv_until(socket, "1\r\n\n\r\n")
    assert response =~ "HTTP/1.1 200 OK\r\n"
    assert response =~ "Transfer-Encoding: chunked\r\n"
    assert response =~ "\r\n\r\n1\r\n\n\r\n"
    assert_receive :traffic_sampled, 2_000
    :gen_tcp.close(socket)
  end

  test "samples authenticated TCP RTT on the pinned ten-second lifecycle" do
    start_supervised!({Manual, monotonic_time: 0})
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)

    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()
    parent = self()
    before = Metrics.snapshot()[{:tcp_rtt, "10ms"}]

    reader = fn _socket ->
      send(parent, {:tcp_rtt_read, self()})
      {:ok, 9_000}
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          tcp_rtt: [reader: reader, interval_ms: 10_000]
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    socket = connect_and_send_info(port, server_public, client_private, %ClientInfo{version: 2})

    assert_receive {:tcp_rtt_read, handler}, 2_000
    assert {:ok, <<_server_info_type, length::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)
    assert Metrics.snapshot()[{:tcp_rtt, "10ms"}] == before

    assert :ok = Manual.advance(9_999)
    refute_receive {:tcp_rtt_read, ^handler}, 25
    assert :ok = Manual.advance(1)
    assert_receive {:tcp_rtt_read, ^handler}, 2_000

    assert_eventually(fn -> Metrics.snapshot()[{:tcp_rtt, "10ms"}] == before + 1 end)

    monitor = Process.monitor(handler)
    :gen_tcp.close(socket)
    assert_receive {:DOWN, ^monitor, :process, ^handler, _reason}, 2_000
    assert_eventually(fn -> Manual.pending_timer_count() == 0 end)
  end

  test "a packet sent during a handshake is queued, and server_info still goes first" do
    {server_public, server_private} = Crypto.generate_keypair()
    {sender_public, sender_private} = Crypto.generate_keypair()
    {recipient_public, recipient_private} = Crypto.generate_keypair()
    parent = self()

    # Registration makes the recipient routable; blocking here holds the handler
    # at exactly that point, before its server info is written and before its
    # send loop starts, while the sender floods the new route.
    event_handler = fn
      {:authenticated, ^recipient_public, _info} = event ->
        send(parent, {:registering, self()})

        receive do
          :flooded -> :ok
        after
          2_000 -> :ok
        end

        send(parent, event)
        :ok

      event ->
        send(parent, event)
        :ok
    end

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_options: [ip: {127, 0, 0, 1}],
        num_acceptors: 1,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public,
          event_handler: event_handler
        ]
      )

    stop_server_on_exit(server)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    sender = connect_and_send_info(port, server_public, sender_private, %ClientInfo{version: 2})
    assert_receive {:authenticated, ^sender_public, _sender_info}, 2_000
    assert {:ok, <<_type, length::unsigned-big-32>>} = :gen_tcp.recv(sender, 5, 2_000)
    assert {:ok, _server_info} = :gen_tcp.recv(sender, length, 2_000)

    recipient =
      connect_and_send_info(port, server_public, recipient_private, %ClientInfo{version: 2})

    assert_receive {:registering, handler}, 2_000

    packet = IO.iodata_to_binary(Frame.encode(:send_packet, [recipient_public, "flood"]))
    before = Metrics.snapshot()
    for _ <- 1..64, do: :ok = :gen_tcp.send(sender, packet)
    assert_receive {:client_message, {:send_packet, ^recipient_public, "flood"}}, 2_000

    # The flood is in the recipient's queues, which no writer is draining yet.
    Process.sleep(50)
    send(handler, :flooded)

    assert {:ok, <<first_type, first_length::unsigned-big-32>>} =
             :gen_tcp.recv(recipient, 5, 2_000)

    assert first_type == Frame.type(:server_info)
    assert {:ok, body} = :gen_tcp.recv(recipient, first_length, 2_000)

    assert Handshake.decode_server_info(body, recipient_private, server_public) ==
             {:ok, %Derpex.ServerInfo{version: 2}}

    # The packets that arrived mid-handshake were queued, not refused: the
    # recipient was already registered when they were routed.
    assert {:ok, <<packet_type, _length::unsigned-big-32>>} = :gen_tcp.recv(recipient, 5, 2_000)
    assert packet_type == Frame.type(:recv_packet)

    current = Metrics.snapshot()

    for kind <- [:disco, :other] do
      assert current[{:packets_dropped, :unknown_dest, kind}] ==
               before[{:packets_dropped, :unknown_dest, kind}]
    end

    :gen_tcp.close(sender)
    :gen_tcp.close(recipient)
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

  defp recv_until(socket, expected, received \\ "", attempts \\ 10)

  defp recv_until(socket, expected, received, attempts) when attempts > 0 do
    if String.contains?(received, expected) do
      {:ok, received}
    else
      case :gen_tcp.recv(socket, 0, 2_000) do
        {:ok, data} -> recv_until(socket, expected, received <> data, attempts - 1)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp recv_until(_socket, expected, received, 0) do
    if String.contains?(received, expected),
      do: {:ok, received},
      else: {:error, :too_many_reads}
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
