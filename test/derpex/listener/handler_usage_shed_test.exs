defmodule Derpex.Listener.HandlerUsageShedTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake
  alias Derpex.Listener.Handler
  alias Derpex.Secret

  defmodule SpoolFullPolicy do
    @moduledoc false

    @behaviour Derpex.Admission

    @impl true
    def authorize(_request, _parent), do: {:ok, %{organization_id: "org_01"}}

    @impl true
    def claim(_request, context, _connection, _parent), do: {:ok, context}

    @impl true
    def release(_connection, _parent), do: :ok

    @impl true
    def reserve_bytes(_context, _bytes, parent) do
      send(parent, {:shed, :reserve_bytes, self()})
      receive do: (:release -> {:error, :usage_spool_full})
    end

    @impl true
    def record_usage(_context, _bytes, _outcome, parent) do
      send(parent, {:shed, :record_usage, self()})
      receive do: (:release -> {:error, :usage_spool_full})
    end
  end

  defmodule RecordUsageFullPolicy do
    @moduledoc false

    @behaviour Derpex.Admission

    @impl true
    def authorize(_request, _parent), do: {:ok, %{organization_id: "org_01"}}

    @impl true
    def claim(_request, context, _connection, _parent), do: {:ok, context}

    @impl true
    def release(_connection, _parent), do: :ok

    @impl true
    def reserve_bytes(_context, _bytes, _parent), do: {:ok, 0}

    @impl true
    def record_usage(_context, _bytes, _outcome, parent) do
      send(parent, {:shed, :record_usage, self()})
      receive do: (:release -> {:error, :usage_spool_full})
    end
  end

  defmodule UsageUnavailablePolicy do
    @moduledoc false

    @behaviour Derpex.Admission

    @impl true
    def authorize(_request, _parent), do: {:ok, %{organization_id: "org_01"}}

    @impl true
    def claim(_request, context, _connection, _parent), do: {:ok, context}

    @impl true
    def release(_connection, _parent), do: :ok

    @impl true
    def reserve_bytes(_context, _bytes, _parent), do: {:ok, 0}

    @impl true
    def record_usage(_context, _bytes, _outcome, parent) do
      send(parent, {:shed, :record_usage, self()})
      receive do: (:release -> {:error, :usage_unavailable})
    end
  end

  test "a full usage spool closes the connection without a crash report" do
    assert_clean_shed(SpoolFullPolicy, :reserve_bytes)
  end

  test "any other usage failure is logged and still closes cleanly" do
    log = assert_clean_shed(UsageUnavailablePolicy, :record_usage, expect_quiet: false)
    assert log =~ "usage-accounting failure"
    assert log =~ "usage_unavailable"
  end

  test "a usage record that cannot be spooled closes the connection cleanly" do
    assert_clean_shed(RecordUsageFullPolicy, :record_usage)
  end

  defp assert_clean_shed(policy, expected_shed, options \\ []) do
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
          admission: {policy, self()}
        ]
      )

    on_exit(fn -> if Process.alive?(server), do: Process.exit(server, :shutdown) end)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    log =
      capture_log(fn ->
        socket = connect_and_send_info(port, server_public, client_private)
        destination = :binary.copy(<<0xDD>>, 32)
        :ok = :gen_tcp.send(socket, Frame.encode(:send_packet, [destination, "data"]))

        assert_receive {:shed, ^expected_shed, handler}, 2_000
        monitor = Process.monitor(handler)
        send(handler, :release)

        # A shed connection stops cleanly: no crash report, no error exit reason.
        assert_receive {:DOWN, ^monitor, :process, ^handler, reason}, 2_000
        assert reason in [:normal, {:shutdown, :local_closed}]
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
      end)

    refute log =~ "terminating"
    refute log =~ "(exit)"
    if Keyword.get(options, :expect_quiet, true), do: refute(log =~ "usage_spool_full")
    log
  end

  defp connect_and_send_info(port, server_public, client_private) do
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

    assert {:ok, <<_server_key_type, 40::unsigned-big-32>>} = :gen_tcp.recv(socket, 5, 2_000)
    assert {:ok, _greeting} = :gen_tcp.recv(socket, 40, 2_000)

    {:ok, client_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{})

    :ok = :gen_tcp.send(socket, client_frame)

    assert {:ok, <<_server_info_type, length::unsigned-big-32>>} =
             :gen_tcp.recv(socket, 5, 2_000)

    assert {:ok, _server_info} = :gen_tcp.recv(socket, length, 2_000)
    socket
  end
end
