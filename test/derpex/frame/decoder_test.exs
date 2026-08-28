defmodule Derpex.Frame.DecoderTest do
  use ExUnit.Case, async: true

  alias Derpex.Frame
  alias Derpex.Frame.Decoder

  @stream IO.iodata_to_binary([
            Frame.encode(:keep_alive, ""),
            Frame.encode(:ping, "12345678"),
            Frame.encode(0xFE, "future"),
            Frame.encode(:health, "healthy")
          ])

  test "decodes every single split boundary without changing frames" do
    expected = [
      {Frame.type(:keep_alive), ""},
      {Frame.type(:ping), "12345678"},
      {0xFE, "future"},
      {Frame.type(:health), "healthy"}
    ]

    for split <- 0..byte_size(@stream) do
      <<first::binary-size(^split), second::binary>> = @stream
      assert decode_chunks([first, second]) == expected
    end
  end

  test "decodes a stream delivered one byte at a time" do
    chunks = for <<byte <- @stream>>, do: <<byte>>

    assert decode_chunks(chunks) == [
             {Frame.type(:keep_alive), ""},
             {Frame.type(:ping), "12345678"},
             {0xFE, "future"},
             {Frame.type(:health), "healthy"}
           ]
  end

  test "rejects an oversized frame immediately after its header" do
    decoder = Decoder.new(max_frame_length: 64)
    input = Frame.encode_header(:send_packet, 65) <> :binary.copy(<<1>>, 1_000)

    assert Decoder.push(decoder, input) == {:error, {:frame_too_large, 65, 64}}
  end

  test "reports clean and truncated stream endings" do
    assert Decoder.finish(Decoder.new()) == :ok

    assert {:ok, [], decoder} = Decoder.push(Decoder.new(), <<Frame.type(:ping), 0, 0>>)
    assert Decoder.finish(decoder) == {:error, :unexpected_eof}

    assert {:ok, [], decoder} =
             Decoder.push(Decoder.new(), Frame.encode_header(:ping, 8) <> "short")

    assert Decoder.finish(decoder) == {:error, :unexpected_eof}
  end

  test "supports a zero maximum for control-only parsing" do
    decoder = Decoder.new(max_frame_length: 0)

    assert {:ok, [{type, ""}], decoder} =
             Decoder.push(decoder, Frame.encode_header(:keep_alive, 0))

    assert type == Frame.type(:keep_alive)
    assert Decoder.finish(decoder) == :ok
  end

  defp decode_chunks(chunks) do
    {frames, decoder} =
      Enum.reduce(chunks, {[], Decoder.new()}, fn chunk, {frames, decoder} ->
        {:ok, decoded, decoder} = Decoder.push(decoder, chunk)
        {frames ++ decoded, decoder}
      end)

    assert Decoder.finish(decoder) == :ok
    frames
  end
end
