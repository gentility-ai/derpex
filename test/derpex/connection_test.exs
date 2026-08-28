defmodule Derpex.ConnectionTest do
  use ExUnit.Case, async: true

  alias Derpex.ClientInfo
  alias Derpex.Connection
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake

  test "emits the greeting before a ten-second handshake deadline" do
    {_server_public, server_private} = Crypto.generate_keypair()

    assert {:ok, state, [{:send, greeting}, {:set_timeout, :handshake, 10_000}]} =
             Connection.new(server_private)

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

    {:ok, state, _initial_actions} = Connection.new(server_private)

    {state, actions} =
      frame
      |> IO.iodata_to_binary()
      |> :binary.bin_to_list()
      |> Enum.reduce({state, []}, fn byte, {state, all_actions} ->
        {:ok, state, actions} = Connection.receive_data(state, <<byte>>)
        {state, all_actions ++ actions}
      end)

    assert [
             {:authenticated, ^client_public, ^client_info},
             {:send, server_info_frame},
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
    {:ok, state, _actions} = Connection.new(server_private)

    assert {:ok, _state, actions} =
             Connection.receive_data(
               state,
               IO.iodata_to_binary([client_info_frame, packet_frame])
             )

    assert [
             {:authenticated, ^client_public, ^client_info},
             {:send, _server_info},
             {:cancel_timeout, :handshake},
             {:set_timeout, :keep_alive, _interval},
             :activity,
             {:client_message, {:send_packet, ^destination, "packet"}}
           ] = actions
  end

  test "emits keepalives at one stable per-connection jittered interval" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    {:ok, state, _actions} = Connection.new(server_private, keep_alive_jitter: 4_999)

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

  test "closes on the wrong first frame, malformed bodies, and handshake timeout" do
    {_server_public, server_private} = Crypto.generate_keypair()
    {:ok, state, _actions} = Connection.new(server_private)

    assert {:close, closed, {:unexpected_handshake_frame, type}, []} =
             Connection.receive_data(state, IO.iodata_to_binary(Frame.encode(:ping, "12345678")))

    assert type == Frame.type(:ping)
    assert Connection.info(closed).phase == :closed

    {:ok, state, _actions} = Connection.new(server_private)
    assert {:close, _state, :handshake_timeout, []} = Connection.timeout(state, :handshake)
  end

  test "ignores unknown authenticated frames but closes on invalid known frames" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    {:ok, client_info_frame} =
      Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    {:ok, state, _actions} = Connection.new(server_private)

    {:ok, state, _actions} =
      Connection.receive_data(state, IO.iodata_to_binary(client_info_frame))

    assert {:ok, state, [:activity]} =
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

    {:ok, state, _actions} = Connection.new(server_private)

    {:ok, state, _actions} =
      Connection.receive_data(state, IO.iodata_to_binary(client_info_frame))

    header = Frame.encode_header(0xFE, 0xFFFFFFFF)
    assert {:ok, state, []} = Connection.receive_data(state, header <> :binary.copy(<<1>>, 128))
    assert state.decoder.remaining == 0xFFFFFFFF - 128
    assert state.decoder.fragments == []
  end
end
