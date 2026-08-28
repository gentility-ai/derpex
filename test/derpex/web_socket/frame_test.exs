defmodule Derpex.WebSocket.FrameTest do
  use ExUnit.Case, async: true

  alias Derpex.WebSocket.Frame

  test "decodes masked binary messages across every byte boundary" do
    encoded = client_frame(0x2, "DERP over WebSocket")

    for split <- 0..byte_size(encoded) do
      <<first::binary-size(^split), second::binary>> = encoded
      assert {:ok, first_events, decoder} = Frame.push(Frame.new(), first)
      assert {:ok, second_events, _decoder} = Frame.push(decoder, second)
      assert first_events ++ second_events == [{:binary, "DERP over WebSocket"}]
    end
  end

  test "reassembles fragments while handling interleaved control frames" do
    stream = [
      client_frame(0x2, "DERP ", false),
      client_frame(0x9, "ping"),
      client_frame(0x0, "stream", true)
    ]

    assert {:ok, [{:ping, "ping"}, {:binary, "DERP stream"}], _decoder} =
             Frame.push(Frame.new(), IO.iodata_to_binary(stream))
  end

  test "rejects unmasked, reserved, text, and oversized client frames" do
    assert Frame.push(Frame.new(), <<0x82, 0>>) == {:error, :unmasked_client_frame}

    assert Frame.push(Frame.new(), <<0xC2, 0x80, 0, 0, 0, 0>>) ==
             {:error, :reserved_websocket_bits}

    assert Frame.push(Frame.new(), client_frame(0x1, "text")) ==
             {:error, :invalid_websocket_sequence}

    decoder = Frame.new(max_message_length: 3)

    assert Frame.push(decoder, client_frame(0x2, "four")) ==
             {:error, :websocket_message_too_large}
  end

  test "encodes unmasked server frames at every length tier" do
    assert <<0x82, 0>> = Frame.encode_binary("")
    assert <<0x82, 125, _payload::binary-size(125)>> = Frame.encode_binary(:binary.copy("a", 125))

    assert <<0x82, 126, 126::unsigned-big-16, _payload::binary-size(126)>> =
             Frame.encode_binary(:binary.copy("a", 126))

    assert <<0x82, 127, 65_536::unsigned-big-64, _payload::binary-size(65_536)>> =
             Frame.encode_binary(:binary.copy("a", 65_536))

    assert Frame.encode_pong("ping") == <<0x8A, 4, "ping">>
  end

  defp client_frame(opcode, payload, fin? \\ true) do
    mask = <<1, 2, 3, 4>>
    length = byte_size(payload)
    fin = if fin?, do: 1, else: 0

    header =
      cond do
        length < 126 -> <<fin::1, 0::3, opcode::4, 1::1, length::7>>
        length <= 65_535 -> <<fin::1, 0::3, opcode::4, 1::1, 126::7, length::unsigned-big-16>>
        true -> <<fin::1, 0::3, opcode::4, 1::1, 127::7, length::unsigned-big-64>>
      end

    repeated_mask = mask |> :binary.copy(div(length + 3, 4)) |> binary_part(0, length)
    header <> mask <> :crypto.exor(payload, repeated_mask)
  end
end
