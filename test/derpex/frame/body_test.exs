# Adapted from Tailscale's DERP client frame-body tests.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Frame.BodyTest do
  use ExUnit.Case, async: true

  alias Derpex.Frame
  alias Derpex.Frame.Body

  @key :binary.copy(<<1>>, 32)
  @ip <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4>>
  @ping <<1, 2, 3, 4, 5, 6, 7, 8>>

  test "decodes the upstream basic server-message vectors" do
    assert Body.decode_server(Frame.type(:ping), @ping) == {:ok, {:ping, @ping}}
    assert Body.decode_server(Frame.type(:pong), @ping) == {:ok, {:pong, @ping}}
    assert Body.decode_server(Frame.type(:health), "BAD") == {:ok, {:health, "BAD"}}
    assert Body.decode_server(Frame.type(:health), "") == {:ok, {:health, ""}}

    assert Body.decode_server(Frame.type(:restarting), <<1::32, 2::32>>) ==
             {:ok, {:restarting, 1, 2}}
  end

  test "parses peer-present frames from every upstream server era" do
    assert peer_present(@key) == {:ok, {:peer_present, @key, nil, nil, 0, ""}}

    assert peer_present(@key <> @ip <> <<0x1234::16>>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0, ""}}

    assert peer_present(@key <> @ip <> <<0x1234::16, 0x01>>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0x01, ""}}

    assert peer_present(@key <> @ip <> <<0x1234::16, 0x01, 3, "abc">>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0x01, "abc"}}
  end

  test "ignores future, truncated, and invalid app-name extensions like upstream" do
    prefix = @key <> @ip <> <<0x1234::16, 0x01>>

    assert peer_present(prefix <> <<3, "abc", 0xDE, 0xAD>>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0x01, "abc"}}

    assert peer_present(prefix <> <<200, "abc">>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0x01, ""}}

    assert peer_present(prefix <> <<3, 1, 2, 3>>) ==
             {:ok, {:peer_present, @key, @ip, 0x1234, 0x01, ""}}
  end

  test "encodes upstream ping and pong client vectors" do
    assert {:ok, ping} = Body.encode_client({:ping, @ping})
    assert IO.iodata_to_binary(ping) == <<0x12, 0, 0, 0, 8, @ping::binary>>

    assert {:ok, pong} = Body.encode_client({:pong, @ping})
    assert IO.iodata_to_binary(pong) == <<0x13, 0, 0, 0, 8, @ping::binary>>
  end

  test "omits the source prefix for the special zero-source server packet" do
    packet = :binary.copy(<<0xA5>>, 40)
    assert {:ok, encoded} = Body.encode_server({:recv_packet, <<0::256>>, packet})
    assert IO.iodata_to_binary(encoded) == <<Frame.type(:recv_packet), 40::32, packet::binary>>
  end

  test "enforces inbound packet, ping, and control-frame limits before routing" do
    destination = :binary.copy(<<2>>, 32)

    assert Body.decode_client(Frame.type(:send_packet), destination <> "packet") ==
             {:ok, {:send_packet, destination, "packet"}}

    assert Body.decode_client(Frame.type(:send_packet), "short") ==
             {:error, :short_send_packet}

    assert Body.decode_client(
             Frame.type(:send_packet),
             destination <> :binary.copy(<<0>>, 65_537)
           ) == {:error, :packet_too_large}

    assert Body.decode_client(Frame.type(:ping), :binary.copy(<<0>>, 1_001)) ==
             {:error, :ping_too_large}

    assert Body.decode_client(Frame.type(:note_preferred), <<2>>) ==
             {:ok, {:note_preferred, true}}

    assert Body.decode_client(Frame.type(:watch_connections), <<0>>) ==
             {:error, :watch_connections_wrong_size}
  end

  test "distinguishes skipped short server messages from ignored extensions" do
    assert Body.decode_server(Frame.type(:recv_packet), "short") ==
             {:drop, :short_recv_packet}

    assert Body.decode_server(0xFE, "future") == :ignore
    assert Body.decode_client(Frame.type(:pong), @ping) == :ignore
  end

  defp peer_present(payload), do: Body.decode_server(Frame.type(:peer_present), payload)
end
