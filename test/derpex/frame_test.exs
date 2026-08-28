# Adapted from Tailscale's DERP framing tests.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.FrameTest do
  use ExUnit.Case, async: true

  alias Derpex.Frame

  @header_cases [
    {:send_packet, 1_024, <<0x04, 0x00, 0x00, 0x04, 0x00>>},
    {:keep_alive, 0, <<0x06, 0x00, 0x00, 0x00, 0x00>>},
    {:recv_packet, 0xFFFFFFFF, <<0x05, 0xFF, 0xFF, 0xFF, 0xFF>>}
  ]

  describe "decode_header/1" do
    test "matches the upstream header vectors" do
      for {name, length, encoded} <- @header_cases do
        type = Frame.type(name)
        assert {:ok, ^type, ^length, ""} = Frame.decode_header(encoded)
      end
    end

    test "preserves the payload and following bytes as a remainder" do
      binary = <<Frame.type(:ping), 8::unsigned-big-32, "12345678following">>
      ping = Frame.type(:ping)

      assert {:ok, ^ping, 8, "12345678following"} =
               Frame.decode_header(binary)
    end

    test "reports every incomplete header boundary" do
      complete = Frame.encode_header(:send_packet, 1_024)

      for available <- 0..4 do
        missing = 5 - available

        assert {:more, ^missing} =
                 complete |> binary_part(0, available) |> Frame.decode_header()
      end
    end

    test "does not reject unknown extension types" do
      assert {:ok, 0xFE, 3, "body"} = Frame.decode_header(<<0xFE, 3::32, "body">>)
      assert Frame.type_name(0xFE) == :unknown
    end
  end

  describe "encode_header/2" do
    test "matches the upstream header vectors" do
      for {name, length, encoded} <- @header_cases do
        assert Frame.encode_header(name, length) == encoded
        assert Frame.encode_header(Frame.type(name), length) == encoded
      end
    end

    test "encodes a full unsigned 32-bit length" do
      assert Frame.encode_header(0xFF, 0xFFFFFFFF) == <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>
    end
  end

  describe "encode/2" do
    test "keeps payload iodata separate from its header" do
      payload = ["one", ["two"]]

      assert [<<0x13, 0, 0, 0, 6>>, ^payload] = Frame.encode(:pong, payload)
    end

    test "rejects the same unreasonable write size as upstream" do
      payload = :binary.copy(<<0>>, 10 * 1_024 * 1_024 + 1)

      assert_raise ArgumentError, "unreasonably large frame write", fn ->
        Frame.encode(:send_packet, payload)
      end
    end
  end

  test "exposes the normative wire constants" do
    assert Frame.magic() == <<0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91>>
    assert Frame.header_length() == 5
    assert Frame.key_length() == 32
    assert Frame.nonce_length() == 24
    assert Frame.max_packet_size() == 65_536
    assert Frame.max_info_length() == 1_048_576
  end
end
