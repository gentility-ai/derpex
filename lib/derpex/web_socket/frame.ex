defmodule Derpex.WebSocket.Frame do
  @moduledoc "Bounded RFC 6455 framing for the DERP binary byte-stream adapter."

  import Bitwise

  @default_max_message_length 1 * 1_024 * 1_024

  defstruct buffer: "",
            fragmented?: false,
            fragments: [],
            fragment_length: 0,
            max_message_length: @default_max_message_length

  @type event :: {:binary, binary()} | {:ping, binary()} | {:pong, binary()} | {:close, binary()}
  @opaque t :: %__MODULE__{
            buffer: binary(),
            fragmented?: boolean(),
            fragments: [binary()],
            fragment_length: non_neg_integer(),
            max_message_length: pos_integer()
          }

  @doc "Creates a client-frame decoder. Client frames must be masked."
  @spec new(keyword()) :: t()
  def new(options \\ []) do
    %__MODULE__{
      max_message_length: Keyword.get(options, :max_message_length, @default_max_message_length)
    }
  end

  @doc "Consumes arbitrary network chunks and emits complete WebSocket events."
  @spec push(t(), binary()) :: {:ok, [event()], t()} | {:error, atom()}
  def push(%__MODULE__{} = state, data) when is_binary(data) do
    parse(%{state | buffer: state.buffer <> data}, [])
  end

  @doc """
  Encodes one unmasked server binary message.

  Returns iodata: a DERP frame is already a list of a header and a packet, and
  flattening it here would copy every relayed packet.
  """
  @spec encode_binary(iodata()) :: iodata()
  def encode_binary(data), do: encode(0x2, data)

  @doc "Encodes one unmasked server pong control message."
  @spec encode_pong(binary()) :: iodata()
  def encode_pong(payload) when byte_size(payload) <= 125, do: encode(0xA, payload)

  @doc "Encodes one unmasked server close control message."
  @spec encode_close(0..65_535, binary()) :: iodata()
  def encode_close(status, reason \\ "") when byte_size(reason) <= 123,
    do: encode(0x8, <<status::unsigned-big-16, reason::binary>>)

  defp parse(state, events) do
    case decode_frame(state.buffer, state.max_message_length) do
      :more ->
        {:ok, Enum.reverse(events), state}

      {:error, reason} ->
        {:error, reason}

      {:ok, fin?, opcode, payload, rest} ->
        state = %{state | buffer: rest}

        case apply_frame(state, fin?, opcode, payload) do
          {:ok, state, nil} -> parse(state, events)
          {:ok, state, event} -> parse(state, [event | events])
          {:error, reason} -> {:error, reason}
        end
    end
  end

  # Every check before the frame is complete reads integers out of the buffer
  # with :binary.at/2 and never binds a sub-binary of it. A sub-binary marks the
  # buffer unwritable, which turns the next `buffer <> data` from an in-place
  # append into a full copy - quadratic in the size of a frame that arrives in
  # small segments. Only a complete frame is destructured, and there the split
  # has to happen anyway.
  defp decode_frame(buffer, _maximum) when byte_size(buffer) < 2, do: :more

  defp decode_frame(buffer, maximum) do
    first = :binary.at(buffer, 0)
    second = :binary.at(buffer, 1)
    rsv = first &&& 0x70
    opcode = first &&& 0x0F
    fin? = (first &&& 0x80) != 0
    masked? = (second &&& 0x80) != 0
    length_field = second &&& 0x7F

    cond do
      rsv != 0 -> {:error, :reserved_websocket_bits}
      not masked? -> {:error, :unmasked_client_frame}
      opcode >= 0x8 and (not fin? or length_field > 125) -> {:error, :invalid_control_frame}
      true -> decode_length(buffer, fin?, opcode, length_field, maximum)
    end
  end

  defp decode_length(buffer, fin?, opcode, length_field, maximum) when length_field < 126,
    do: decode_payload(buffer, fin?, opcode, 2, length_field, maximum)

  defp decode_length(buffer, _fin?, _opcode, 126, _maximum) when byte_size(buffer) < 4, do: :more

  defp decode_length(buffer, fin?, opcode, 126, maximum) do
    case unsigned(buffer, 2, 2) do
      length when length < 126 -> {:error, :noncanonical_websocket_length}
      length -> decode_payload(buffer, fin?, opcode, 4, length, maximum)
    end
  end

  defp decode_length(buffer, _fin?, _opcode, 127, _maximum) when byte_size(buffer) < 10, do: :more

  defp decode_length(buffer, fin?, opcode, 127, maximum) do
    cond do
      (:binary.at(buffer, 2) &&& 0x80) != 0 -> {:error, :invalid_websocket_length}
      unsigned(buffer, 2, 8) < 65_536 -> {:error, :noncanonical_websocket_length}
      true -> decode_payload(buffer, fin?, opcode, 10, unsigned(buffer, 2, 8), maximum)
    end
  end

  defp decode_payload(_buffer, _fin?, _opcode, _header_length, length, maximum)
       when length > maximum,
       do: {:error, :websocket_message_too_large}

  defp decode_payload(buffer, _fin?, _opcode, header_length, length, _maximum)
       when byte_size(buffer) < header_length + 4 + length,
       do: :more

  defp decode_payload(buffer, fin?, opcode, header_length, length, _maximum) do
    <<_header::binary-size(^header_length), mask::binary-size(4),
      masked_payload::binary-size(^length), remainder::binary>> = buffer

    {:ok, fin?, opcode, unmask(masked_payload, mask), remainder}
  end

  defp unsigned(buffer, offset, count) do
    Enum.reduce(offset..(offset + count - 1), 0, fn index, value ->
      value <<< 8 ||| :binary.at(buffer, index)
    end)
  end

  defp apply_frame(%{fragmented?: false} = state, true, 0x2, payload),
    do: {:ok, state, {:binary, payload}}

  defp apply_frame(%{fragmented?: false} = state, false, 0x2, payload) do
    {:ok, %{state | fragmented?: true, fragments: [payload], fragment_length: byte_size(payload)},
     nil}
  end

  defp apply_frame(%{fragmented?: true} = state, fin?, 0x0, payload) do
    length = state.fragment_length + byte_size(payload)

    if length > state.max_message_length do
      {:error, :websocket_message_too_large}
    else
      fragments = [payload | state.fragments]

      if fin? do
        message = fragments |> Enum.reverse() |> IO.iodata_to_binary()

        {:ok, %{state | fragmented?: false, fragments: [], fragment_length: 0},
         {:binary, message}}
      else
        {:ok, %{state | fragments: fragments, fragment_length: length}, nil}
      end
    end
  end

  defp apply_frame(state, true, 0x8, payload) when byte_size(payload) != 1,
    do: {:ok, state, {:close, payload}}

  defp apply_frame(state, true, 0x9, payload), do: {:ok, state, {:ping, payload}}
  defp apply_frame(state, true, 0xA, payload), do: {:ok, state, {:pong, payload}}
  defp apply_frame(_state, _fin?, _opcode, _payload), do: {:error, :invalid_websocket_sequence}

  defp unmask(payload, mask) do
    mask
    |> :binary.copy(div(byte_size(payload) + 3, 4))
    |> binary_part(0, byte_size(payload))
    |> bxor_binary(payload)
  end

  defp bxor_binary(mask, payload), do: :crypto.exor(mask, payload)

  defp encode(opcode, payload) do
    length = IO.iodata_length(payload)

    header =
      cond do
        length < 126 -> <<1::1, 0::3, opcode::4, 0::1, length::7>>
        length <= 65_535 -> <<1::1, 0::3, opcode::4, 0::1, 126::7, length::unsigned-big-16>>
        true -> <<1::1, 0::3, opcode::4, 0::1, 127::7, length::unsigned-big-64>>
      end

    [header, payload]
  end
end
