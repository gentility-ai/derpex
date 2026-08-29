defmodule Derpex.Frame.DecoderPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Derpex.Frame
  alias Derpex.Frame.Decoder

  @moduletag :property

  # Small enough that the generators can reach it, large enough that a whole
  # frame still has to be buffered across chunks.
  @max_frame_length 4 * 1_024

  # A frame the decoder must retain in full plus one header it has not finished
  # reading is the entire declared working set.
  @retained_cap @max_frame_length + 5

  property "arbitrary chunking decodes to the same frames as the whole stream" do
    check all(
            frames <- list_of(frame(), max_length: 8),
            sizes <- list_of(integer(0..16), max_length: 40)
          ) do
      stream = encode_stream(frames)

      {:ok, whole, whole_decoder} = Decoder.push(decoder(), stream)
      assert whole == frames
      assert Decoder.finish(whole_decoder) == :ok

      {chunked, chunked_decoder} = push_all(decoder(), chunk(stream, sizes))
      assert chunked == frames
      assert Decoder.finish(chunked_decoder) == :ok
    end
  end

  property "a frame split across chunks never reports early completion" do
    check all(
            {type, payload} <- frame(),
            sizes <- list_of(integer(0..8), max_length: 40)
          ) do
      stream = encode_stream([{type, payload}])
      chunks = chunk(stream, sizes)

      {frames, decoder} = push_all(decoder(), chunks)
      assert frames == [{type, payload}]
      assert Decoder.finish(decoder) == :ok

      for prefix <- partial_prefixes(chunks, byte_size(stream)) do
        {partial, partial_decoder} = push_all(decoder(), prefix)
        assert partial == []
        assert Decoder.finish(partial_decoder) == {:error, :unexpected_eof}
      end
    end
  end

  property "arbitrary bytes never raise and stay inside the frame cap" do
    check all(chunks <- list_of(stream_bytes(), max_length: 24)) do
      Enum.reduce_while(chunks, decoder(), fn chunk, decoder ->
        case Decoder.push(decoder, chunk) do
          {:ok, frames, decoder} ->
            assert is_list(frames)
            assert retained(decoder) <= @retained_cap
            {:cont, decoder}

          {:error, {:frame_too_large, declared, limit}} ->
            assert declared > limit
            {:halt, decoder()}
        end
      end)
    end
  end

  property "round trips every frame type and payload length" do
    check all(
            type <- integer(0..255),
            payload <- binary(max_length: 512)
          ) do
      encoded = IO.iodata_to_binary(Frame.encode(type, payload))

      assert {:ok, type_code, length, ^payload} = Frame.decode_header(encoded)
      assert type_code == type
      assert length == byte_size(payload)
      assert {:ok, [{^type, ^payload}], decoder} = Decoder.push(decoder(), encoded)
      assert Decoder.finish(decoder) == :ok
    end
  end

  test "streaming far more than the cap keeps binary memory bounded" do
    frame =
      IO.iodata_to_binary(
        Frame.encode(:send_packet, :crypto.strong_rand_bytes(@max_frame_length))
      )

    chunks = chunk(frame, List.duplicate(512, 64))
    iterations = 10_000

    :erlang.garbage_collect()
    before = :erlang.memory(:binary)

    decoder =
      Enum.reduce(1..iterations, decoder(), fn _iteration, decoder ->
        {frames, decoder} = push_all(decoder, chunks)
        assert length(frames) == 1
        decoder
      end)

    assert retained(decoder) <= @retained_cap
    :erlang.garbage_collect()

    assert iterations * byte_size(frame) > 32 * 1_024 * 1_024
    assert :erlang.memory(:binary) - before < 4 * 1_024 * 1_024
  end

  defp decoder, do: Decoder.new(max_frame_length: @max_frame_length)

  defp frame do
    gen all(
          type <- integer(0..255),
          payload <- binary(max_length: 64)
        ) do
      {type, payload}
    end
  end

  defp stream_bytes do
    one_of([
      binary(max_length: 48),
      map(frame(), fn {type, payload} -> IO.iodata_to_binary(Frame.encode(type, payload)) end),
      map(binary(max_length: 8), &(<<0x04, 3_000::unsigned-big-32>> <> &1)),
      map(binary(max_length: 8), &(<<0x04, 0xFFFFFFFF::unsigned-big-32>> <> &1))
    ])
  end

  defp encode_stream(frames) do
    frames
    |> Enum.map(fn {type, payload} -> Frame.encode(type, payload) end)
    |> IO.iodata_to_binary()
  end

  defp push_all(decoder, chunks) do
    Enum.reduce(chunks, {[], decoder}, fn chunk, {frames, decoder} ->
      {:ok, decoded, decoder} = Decoder.push(decoder, chunk)
      {frames ++ decoded, decoder}
    end)
  end

  defp partial_prefixes(chunks, stream_length) do
    0..length(chunks)
    |> Enum.map(&Enum.take(chunks, &1))
    |> Enum.filter(fn prefix ->
      pushed = Enum.sum_by(prefix, &byte_size/1)
      pushed > 0 and pushed < stream_length
    end)
  end

  defp chunk("", _sizes), do: []
  defp chunk(binary, []), do: [binary]

  defp chunk(binary, [size | sizes]) do
    size = min(size, byte_size(binary))
    <<head::binary-size(^size), tail::binary>> = binary
    [head | chunk(tail, sizes)]
  end

  defp retained(decoder) do
    byte_size(decoder.header) + Enum.sum_by(decoder.fragments, &byte_size/1)
  end
end
