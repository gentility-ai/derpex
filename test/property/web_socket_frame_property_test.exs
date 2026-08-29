defmodule Derpex.WebSocket.FramePropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Derpex.WebSocket.Frame

  @moduletag :property

  @max_message_length 1_024

  # Two length bytes, eight extended-length bytes and a four-byte mask are the
  # only framing the decoder can hold on top of one capped message.
  @buffered_cap @max_message_length + 14

  # Wide enough for the 64-bit extended length to be a legal client frame.
  @extended_message_length 70 * 1_024

  # A process that streams gigabytes through the decoder may still reference the
  # fixture binaries it started with, and nothing else.
  @leak_budget 256 * 1_024

  property "arbitrary chunking decodes to the same events as the whole stream" do
    check all events <- list_of(event(), max_length: 8),
              masks <- list_of(binary(length: 4), min_length: 1, max_length: 4),
              sizes <- list_of(integer(0..12), max_length: 80) do
      stream = encode_client_stream(events, masks)

      assert {:ok, whole, state} = Frame.push(decoder(), stream)
      assert whole == events
      assert state.buffer == ""

      {chunked, chunked_state} = push_all(decoder(), chunk(stream, sizes))
      assert chunked == events
      assert chunked_state.buffer == ""
    end
  end

  property "a fragmented binary message reassembles to the unfragmented one" do
    check all payload <- sized_binary(0, @max_message_length),
              sizes <- list_of(integer(0..64), max_length: 24),
              masks <- list_of(binary(length: 4), min_length: 1, max_length: 4),
              chunk_sizes <- list_of(integer(0..12), max_length: 80) do
      fragments = fragments(payload, sizes)
      stream = encode_fragmented(fragments, masks)

      {events, state} = push_all(decoder(), chunk(stream, chunk_sizes))
      assert events == [{:binary, payload}]
      assert state.buffer == ""
      assert state.fragments == []
    end
  end

  property "server frames round trip through a reference reader" do
    check all payload <- server_payload(),
              control <- sized_binary(0, 123),
              status <- integer(0..65_535) do
      assert read_server_frame(Frame.encode_binary(payload)) == {0x2, payload}

      assert read_server_frame(Frame.encode_binary([payload, control])) ==
               {0x2, payload <> control}

      assert read_server_frame(Frame.encode_pong(control)) == {0xA, control}

      assert read_server_frame(Frame.encode_close(status, control)) ==
               {0x8, <<status::unsigned-big-16, control::binary>>}
    end
  end

  property "decodes both canonical extended client-frame lengths" do
    check all length <- one_of([integer(126..1_000), integer(65_536..66_000)]),
              mask <- binary(length: 4),
              seed <- binary(length: 8),
              sizes <- list_of(integer(0..4_096), max_length: 24) do
      payload = repeat_to(seed, length)
      frame = client_frame(0x2, payload, mask, true)

      assert length_marker(frame) == if(length < 65_536, do: 126, else: 127)

      {events, state} = push_all(decoder(@extended_message_length), chunk(frame, sizes))
      assert events == [{:binary, payload}]
      assert state.buffer == ""
    end
  end

  property "arbitrary bytes never raise and stay inside the message cap" do
    check all chunks <- list_of(stream_bytes(), max_length: 24) do
      Enum.reduce_while(chunks, decoder(), fn chunk, state ->
        case Frame.push(state, chunk) do
          {:ok, events, state} ->
            assert is_list(events)
            assert byte_size(state.buffer) <= @buffered_cap
            assert state.fragment_length <= @max_message_length
            {:cont, state}

          {:error, reason} ->
            assert is_atom(reason)
            {:halt, decoder()}
        end
      end)
    end
  end

  property "rejects rather than buffers a message that outgrows the cap" do
    check all excess <- integer(1..2_048),
              mask <- binary(length: 4) do
      length = @max_message_length + excess
      header = <<1::1, 0::3, 0x2::4, 1::1, 126::7, length::unsigned-big-16>>

      assert Frame.push(decoder(), header <> mask) == {:error, :websocket_message_too_large}
    end
  end

  test "streaming far more than the cap keeps binary memory bounded" do
    payload = :crypto.strong_rand_bytes(@max_message_length)
    frame = client_frame(0x2, payload, <<1, 2, 3, 4>>, true)
    chunks = chunk(frame, List.duplicate(128, 32))
    iterations = 40_000
    before = referenced_binary_bytes()

    state =
      Enum.reduce(1..iterations, decoder(), fn _iteration, state ->
        {events, state} = push_all(state, chunks)
        assert events == [{:binary, payload}]
        state
      end)

    assert byte_size(state.buffer) <= @buffered_cap
    assert iterations * byte_size(frame) > 32 * 1_024 * 1_024
    assert referenced_binary_bytes() - before < @leak_budget
  end

  defp decoder(max_message_length \\ @max_message_length) do
    Frame.new(max_message_length: max_message_length)
  end

  defp event do
    one_of([
      map(sized_binary(0, @max_message_length), &{:binary, &1}),
      map(sized_binary(0, 125), &{:ping, &1}),
      map(sized_binary(0, 125), &{:pong, &1}),
      map(control_payload(), &{:close, &1})
    ])
  end

  # A one-byte close payload is a protocol error rather than a close event.
  defp control_payload do
    one_of([constant(""), sized_binary(2, 125)])
  end

  # Reaches both canonical extended-length encodings without regenerating a
  # large binary on every run.
  defp server_payload do
    one_of([sized_binary(0, 300), constant(:crypto.strong_rand_bytes(70_000))])
  end

  # `binary(max_length: n)` is also bounded by the generation size, which stays
  # near 100 for a default run count. Driving the length with an integer reaches
  # the declared caps, and the 126-byte extended-length boundary, on every run.
  defp sized_binary(min_length, max_length) do
    bind(integer(min_length..max_length), &binary(length: &1))
  end

  defp repeat_to(seed, length) do
    seed
    |> :binary.copy(div(length, byte_size(seed)) + 1)
    |> binary_part(0, length)
  end

  defp length_marker(<<_flags_and_opcode::9, marker::7, _rest::binary>>), do: marker

  defp stream_bytes do
    one_of([
      binary(max_length: 64),
      map({event(), binary(length: 4)}, fn {event, mask} ->
        encode_client_stream([event], [mask])
      end),
      map(binary(length: 4), &(<<1::1, 0::3, 0x2::4, 1::1, 126::7, 900::unsigned-big-16>> <> &1)),
      map(
        binary(length: 4),
        &(<<1::1, 0::3, 0x2::4, 1::1, 127::7, 0::1, 1_099_511_627_776::63>> <> &1)
      )
    ])
  end

  defp encode_client_stream(events, masks) do
    events
    |> Enum.zip(Stream.cycle(masks))
    |> Enum.map_join("", fn {event, mask} ->
      client_frame(opcode(event), payload(event), mask, true)
    end)
  end

  defp encode_fragmented([payload], masks) do
    client_frame(0x2, payload, hd(masks), true)
  end

  defp encode_fragmented([first | rest], masks) do
    {continuations, [last]} = Enum.split(rest, length(rest) - 1)

    masked =
      [{0x2, first, false}] ++
        Enum.map(continuations, &{0x0, &1, false}) ++ [{0x0, last, true}]

    masked
    |> Enum.zip(Stream.cycle(masks))
    |> Enum.map_join("", fn {{opcode, part, fin?}, mask} ->
      client_frame(opcode, part, mask, fin?)
    end)
  end

  defp opcode({:binary, _payload}), do: 0x2
  defp opcode({:ping, _payload}), do: 0x9
  defp opcode({:pong, _payload}), do: 0xA
  defp opcode({:close, _payload}), do: 0x8

  defp payload({_type, payload}), do: payload

  defp client_frame(opcode, payload, mask, fin?) do
    length = byte_size(payload)
    fin = if fin?, do: 1, else: 0

    header =
      cond do
        length < 126 -> <<fin::1, 0::3, opcode::4, 1::1, length::7>>
        length <= 65_535 -> <<fin::1, 0::3, opcode::4, 1::1, 126::7, length::unsigned-big-16>>
        true -> <<fin::1, 0::3, opcode::4, 1::1, 127::7, length::unsigned-big-64>>
      end

    header <> mask <> :crypto.exor(repeat_mask(mask, length), payload)
  end

  defp repeat_mask(mask, length) do
    mask
    |> :binary.copy(div(length + 3, 4))
    |> binary_part(0, length)
  end

  defp read_server_frame(
         <<1::1, 0::3, opcode::4, 0::1, 127::7, length::unsigned-big-64, rest::binary>>
       )
       when length > 65_535 do
    {opcode, match_payload(rest, length)}
  end

  defp read_server_frame(
         <<1::1, 0::3, opcode::4, 0::1, 126::7, length::unsigned-big-16, rest::binary>>
       )
       when length in 126..65_535 do
    {opcode, match_payload(rest, length)}
  end

  defp read_server_frame(<<1::1, 0::3, opcode::4, 0::1, length::7, rest::binary>>)
       when length < 126 do
    {opcode, match_payload(rest, length)}
  end

  defp match_payload(rest, length) do
    <<payload::binary-size(^length)>> = rest
    payload
  end

  defp fragments(payload, sizes) do
    case chunk(payload, sizes) do
      [] -> [""]
      parts -> parts
    end
  end

  defp push_all(state, chunks) do
    Enum.reduce(chunks, {[], state}, fn chunk, {events, state} ->
      {:ok, decoded, state} = Frame.push(state, chunk)
      {events ++ decoded, state}
    end)
  end

  defp chunk("", _sizes), do: []
  defp chunk(binary, []), do: [binary]

  defp chunk(binary, [size | sizes]) do
    size = min(size, byte_size(binary))
    <<head::binary-size(^size), tail::binary>> = binary
    [head | chunk(tail, sizes)]
  end

  # `:erlang.memory(:binary)` is VM-global and moves under any concurrent test;
  # the refc binaries this process still holds after a collection are the signal
  # a retained sub-binary would show up in.
  defp referenced_binary_bytes do
    :erlang.garbage_collect()
    {:binary, references} = Process.info(self(), :binary)
    Enum.sum_by(references, &elem(&1, 1))
  end
end
