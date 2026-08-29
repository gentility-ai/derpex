defmodule Derpex.ConnectionTest.StateHolder do
  @moduledoc false

  use GenServer

  def start(state), do: GenServer.start(__MODULE__, state)

  @impl true
  def init(state), do: {:ok, state}

  @impl true
  def handle_cast(:crash, state), do: {:stop, :deliberate_crash, state}
end

defmodule Derpex.ConnectionTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Derpex.ClientInfo
  alias Derpex.Connection
  alias Derpex.ConnectionTest.StateHolder
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake
  alias Derpex.Secret

  test "emits the greeting before a ten-second handshake deadline" do
    {_server_public, server_private} = Crypto.generate_keypair()

    assert {:ok, state, [{:send, greeting}, {:set_timeout, :handshake, 10_000}]} =
             Connection.new(Secret.wrap(server_private))

    assert {:ok, type, 40, body} = greeting |> IO.iodata_to_binary() |> Frame.decode_header()
    assert type == Frame.type(:server_key)
    assert Handshake.decode_server_key(body) |> elem(0) == :ok
    assert Connection.info(state).phase == :awaiting_client_info
  end

  test "authenticates a client-info frame split at every byte boundary" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    client_info = %ClientInfo{version: 2, can_ack_pings: true, app_name: "chunked"}
    {:ok, frame} = Handshake.client_info_frame(client_private, server_public, client_info)

    {:ok, state, _initial_actions} = Connection.new(Secret.wrap(server_private))

    {state, actions} =
      frame
      |> IO.iodata_to_binary()
      |> :binary.bin_to_list()
      |> Enum.reduce({state, []}, fn byte, {state, all_actions} ->
        {:ok, state, actions} = Connection.receive_data(state, <<byte>>)
        {state, all_actions ++ actions}
      end)

    assert [
             {:authenticated, ^client_public, ^client_info, false},
             {:send, server_info_frame},
             {:register, ^client_public, ^client_info, false},
             {:cancel_timeout, :handshake},
             {:set_timeout, :keep_alive, keep_alive_interval}
           ] = actions

    assert keep_alive_interval in 60_000..64_999

    assert Connection.info(state).phase == :authenticated

    assert {:ok, type, _length, server_info_body} =
             server_info_frame |> IO.iodata_to_binary() |> Frame.decode_header()

    assert type == Frame.type(:server_info)

    assert Handshake.decode_server_info(server_info_body, client_private, server_public) ==
             {:ok, %Derpex.ServerInfo{version: 2}}
  end

  test "orders registration and server info before a pipelined packet" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    destination = :binary.copy(<<9>>, 32)
    client_info = %ClientInfo{version: 2}

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, client_info)

    packet_frame = Frame.encode(:send_packet, [destination, "packet"])
    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    assert {:ok, _state, actions} =
             Connection.receive_data(
               state,
               IO.iodata_to_binary([client_info_frame, packet_frame])
             )

    assert [
             {:authenticated, ^client_public, ^client_info, false},
             {:send, _server_info},
             {:register, ^client_public, ^client_info, false},
             {:cancel_timeout, :handshake},
             {:set_timeout, :keep_alive, _interval},
             {:rate_limit, 38},
             :activity,
             {:client_message, {:send_packet, ^destination, "packet"}}
           ] = actions
  end

  test "emits keepalives at one stable per-connection jittered interval" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private), keep_alive_jitter: 4_999)

    assert {:ok, state, actions} =
             Connection.receive_data(state, IO.iodata_to_binary(client_info_frame))

    assert {:set_timeout, :keep_alive, 64_999} in actions

    assert Connection.timeout(state, :keep_alive) ==
             {:ok, state,
              [
                {:server_message, :keep_alive},
                {:set_timeout, :keep_alive, 64_999}
              ]}
  end

  test "only a constant-time authenticated mesh peer may watch connections" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()
    mesh_key = :binary.copy(<<7>>, 32)
    client_info = %ClientInfo{version: 2, mesh_key: mesh_key}

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, client_info)

    watch_frame = Frame.encode(:watch_connections, "")

    {:ok, state, _actions} =
      Connection.new(Secret.wrap(server_private), mesh_key: Secret.wrap(mesh_key))

    assert {:ok, state, actions} =
             Connection.receive_data(state, IO.iodata_to_binary([client_info_frame, watch_frame]))

    assert [
             {:authenticated, ^client_public, ^client_info, true},
             {:send, _server_info},
             {:register, ^client_public, ^client_info, true},
             {:cancel_timeout, :handshake},
             {:set_timeout, :keep_alive, _interval},
             {:rate_limit, 0},
             :activity,
             {:client_message, :watch_connections}
           ] = actions

    assert Connection.info(state).can_mesh

    {:ok, untrusted, _actions} =
      Connection.new(Secret.wrap(server_private), mesh_key: Secret.wrap(:binary.copy(<<8>>, 32)))

    assert {:close, _state, :insufficient_permissions, prior_actions} =
             Connection.receive_data(
               untrusted,
               IO.iodata_to_binary([client_info_frame, watch_frame])
             )

    assert [{:authenticated, ^client_public, ^client_info, false} | _rest] = prior_actions
  end

  test "closes on the wrong first frame, malformed bodies, and handshake timeout" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    assert {:close, closed, {:unexpected_handshake_frame, type}, []} =
             Connection.receive_data(state, IO.iodata_to_binary(Frame.encode(:ping, "12345678")))

    assert type == Frame.type(:ping)
    assert Connection.info(closed).phase == :closed

    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))
    assert {:close, _state, :handshake_timeout, []} = Connection.timeout(state, :handshake)
  end

  test "ignores unknown authenticated frames but closes on invalid known frames" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    {:ok, state, _actions} =
      Connection.receive_data(state, IO.iodata_to_binary(client_info_frame))

    assert {:ok, state, [{:rate_limit, 6}, :activity]} =
             Connection.receive_data(state, IO.iodata_to_binary(Frame.encode(0xFE, "future")))

    assert {:close, _state, :note_preferred_wrong_size, []} =
             Connection.receive_data(
               state,
               IO.iodata_to_binary(Frame.encode(:note_preferred, "wrong"))
             )
  end

  test "streams unknown authenticated frames to discard without retaining their bodies" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    {:ok, state, _actions} =
      Connection.receive_data(state, IO.iodata_to_binary(client_info_frame))

    header = Frame.encode_header(0xFE, 0xFFFFFFFF)
    assert {:ok, state, []} = Connection.receive_data(state, header <> :binary.copy(<<1>>, 128))
    assert state.decoder.remaining == 0xFFFFFFFF - 128
    assert state.decoder.fragments == []
  end

  test "closes a wrong first frame on its header rather than after its body" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    {microseconds, result} =
      :timer.tc(fn -> Connection.receive_data(state, <<0xFF, 0xFFFFFFFF::32>>) end)

    assert {:close, closed, {:unexpected_handshake_frame, 0xFF}, []} = result
    assert Connection.info(closed).phase == :closed
    assert microseconds < 100_000
  end

  test "closes on a client-info frame below Go's key-and-nonce minimum" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    at_minimum = Frame.encode_header(Frame.type(:client_info), 56)
    assert {:ok, _state, []} = Connection.receive_data(state, IO.iodata_to_binary(at_minimum))

    below_minimum = Frame.encode_header(Frame.type(:client_info), 55)

    assert {:close, closed, {:frame_too_small, 55, 56}, []} =
             Connection.receive_data(state, IO.iodata_to_binary(below_minimum))

    assert Connection.info(closed).phase == :closed
  end

  test "closes on a client-info frame above the pre-authentication cap" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, state, _actions} = Connection.new(Secret.wrap(server_private))

    at_cap = Frame.encode_header(Frame.type(:client_info), 16 * 1_024)
    assert {:ok, _state, []} = Connection.receive_data(state, IO.iodata_to_binary(at_cap))

    above_cap = Frame.encode_header(Frame.type(:client_info), 17 * 1_024)

    assert {:close, closed, {:frame_too_large, 17_408, 16_384}, []} =
             Connection.receive_data(state, IO.iodata_to_binary(above_cap))

    assert Connection.info(closed).phase == :closed
  end

  test "keeps the server private key and mesh key out of inspected state" do
    {_server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, state, _actions} =
      Connection.new(Secret.wrap(server_private), mesh_key: Secret.wrap(mesh_key))

    rendered = inspect(state, limit: :infinity, structs: false, binaries: :as_binaries)

    refute rendered =~ Base.encode16(server_private)
    refute rendered =~ inspect(server_private, limit: :infinity, binaries: :as_binaries)
    refute rendered =~ Base.encode16(mesh_key)
    refute rendered =~ inspect(mesh_key, limit: :infinity, binaries: :as_binaries)
  end

  test "keeps key material out of a crash report carrying connection state" do
    {_server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, state, _actions} =
      Connection.new(Secret.wrap(server_private), mesh_key: Secret.wrap(mesh_key))

    log =
      capture_log(fn ->
        {:ok, holder} = StateHolder.start(state)
        reference = Process.monitor(holder)
        GenServer.cast(holder, :crash)
        assert_receive {:DOWN, ^reference, :process, ^holder, :deliberate_crash}, 1_000
      end)

    assert log =~ "deliberate_crash"
    refute log =~ Base.encode16(server_private)
    refute log =~ inspect(server_private, limit: :infinity, binaries: :as_binaries)
    refute log =~ Base.encode16(mesh_key)
    refute log =~ inspect(mesh_key, limit: :infinity, binaries: :as_binaries)
  end
end
