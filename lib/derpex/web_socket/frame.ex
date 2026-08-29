defmodule Derpex.WebSocket.Frame do
  @moduledoc "Bounded RFC 6455 framing for the DERP binary byte-stream adapter."

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

  defp decode_frame(buffer, _maximum) when byte_size(buffer) < 2, do: :more

  defp decode_frame(<<fin::1, rsv::3, opcode::4, masked::1, length::7, rest::binary>>, maximum) do
    cond do
      rsv != 0 -> {:error, :reserved_websocket_bits}
      masked != 1 -> {:error, :unmasked_client_frame}
      opcode >= 0x8 and (fin != 1 or length > 125) -> {:error, :invalid_control_frame}
      true -> decode_extended_length(fin == 1, opcode, length, rest, maximum)
    end
  end

  defp decode_extended_length(fin?, opcode, length, rest, maximum) when length < 126 do
    decode_masked_payload(fin?, opcode, length, rest, maximum)
  end

  defp decode_extended_length(_fin?, _opcode, 126, rest, _maximum) when byte_size(rest) < 2,
    do: :more

  defp decode_extended_length(
         fin?,
         opcode,
         126,
         <<length::unsigned-big-16, rest::binary>>,
         maximum
       ) do
    if length < 126 do
      {:error, :noncanonical_websocket_length}
    else
      decode_masked_payload(fin?, opcode, length, rest, maximum)
    end
  end

  defp decode_extended_length(_fin?, _opcode, 127, rest, _maximum) when byte_size(rest) < 8,
    do: :more

  defp decode_extended_length(
         fin?,
         opcode,
         127,
         <<0::1, length::unsigned-big-63, rest::binary>>,
         maximum
       ) do
    if length < 65_536 do
      {:error, :noncanonical_websocket_length}
    else
      decode_masked_payload(fin?, opcode, length, rest, maximum)
    end
  end

  defp decode_extended_length(_fin?, _opcode, 127, _rest, _maximum),
    do: {:error, :invalid_websocket_length}

  defp decode_masked_payload(_fin?, _opcode, length, _rest, maximum) when length > maximum,
    do: {:error, :websocket_message_too_large}

  defp decode_masked_payload(_fin?, _opcode, length, rest, _maximum)
       when byte_size(rest) < 4 + length,
       do: :more

  defp decode_masked_payload(
         fin?,
         opcode,
         length,
         <<mask::binary-size(4), rest::binary>>,
         _maximum
       ) do
    <<masked_payload::binary-size(^length), remainder::binary>> = rest
    {:ok, fin?, opcode, unmask(masked_payload, mask), remainder}
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
