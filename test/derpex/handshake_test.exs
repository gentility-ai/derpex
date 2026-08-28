defmodule Derpex.HandshakeTest do
  use ExUnit.Case, async: true

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Handshake
  alias Derpex.ServerInfo

  test "round trips the authenticated three-frame handshake" do
    {server_public, server_private} = Crypto.generate_keypair()
    {client_public, client_private} = Crypto.generate_keypair()

    assert {:ok, greeting} = Handshake.server_key_frame(server_private)
    assert {:server_key, greeting_body} = unpack(greeting)
    assert greeting_body == Frame.magic() <> server_public
    assert Handshake.decode_server_key(greeting_body) == {:ok, server_public}

    client_info = %ClientInfo{
      version: Handshake.protocol_version(),
      can_ack_pings: true,
      app_name: "derpex-test"
    }

    assert {:ok, encoded_client_info} =
             Handshake.client_info_frame(client_private, server_public, client_info)

    assert {:client_info, client_info_body} = unpack(encoded_client_info)

    assert Handshake.decode_client_info(client_info_body, server_private) ==
             {:ok, client_public, client_info}

    server_info = %ServerInfo{
      version: Handshake.protocol_version(),
      token_bucket_bytes_per_second: 1_000,
      token_bucket_bytes_burst: 2_000
    }

    assert {:ok, encoded_server_info} =
             Handshake.server_info_frame(server_private, client_public, server_info)

    assert {:server_info, server_info_body} = unpack(encoded_server_info)

    assert Handshake.decode_server_info(server_info_body, client_private, server_public) ==
             {:ok, server_info}
  end

  test "accepts bounded server-greeting extensions but rejects bad greetings" do
    {server_public, _server_private} = Crypto.generate_keypair()

    assert Handshake.decode_server_key(Frame.magic() <> server_public <> "future") ==
             {:ok, server_public}

    assert Handshake.decode_server_key("NOTDERP!" <> server_public) ==
             {:error, :invalid_server_greeting}

    assert Handshake.decode_server_key(:binary.copy(<<0>>, 1_025)) ==
             {:error, :server_greeting_too_large}
  end

  test "rejects unauthenticated and resource-exhausting information frames" do
    {server_public, server_private} = Crypto.generate_keypair()
    {_client_public, client_private} = Crypto.generate_keypair()

    assert Handshake.decode_client_info(:binary.copy(<<0>>, 55), server_private) ==
             {:error, :short_client_info}

    assert Handshake.decode_client_info(:binary.copy(<<0>>, 256 * 1_024 + 1), server_private) ==
             {:error, :long_client_info}

    assert {:ok, frame} =
             Handshake.client_info_frame(client_private, server_public, %ClientInfo{version: 2})

    assert {:client_info, body} = unpack(frame)
    prefix_size = byte_size(body) - 1
    <<prefix::binary-size(^prefix_size), last>> = body
    tampered = <<prefix::binary, rem(last + 1, 256)>>

    assert Handshake.decode_client_info(tampered, server_private) ==
             {:error, :cannot_open_client_info}

    assert Handshake.decode_server_info("short", client_private, server_public) ==
             {:error, :short_server_info}
  end

  defp unpack(frame) do
    binary = IO.iodata_to_binary(frame)
    {:ok, type, length, payload} = Frame.decode_header(binary)
    assert byte_size(payload) == length
    {:ok, name} = Frame.type_name(type)
    {name, payload}
  end
end
