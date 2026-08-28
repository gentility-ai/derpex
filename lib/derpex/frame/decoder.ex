defmodule Derpex.Frame.Decoder do
  @moduledoc """
  Incremental DERP frame decoder for arbitrary byte-stream chunks.

  Only the five-byte header is accumulated before its unsigned length is
  checked. Payload fragments are retained as sub-binaries and copied once only
  when a frame spans multiple transport chunks.
  """

  alias Derpex.Frame

  @default_max_frame_length 1 * 1_024 * 1_024

  defstruct header: "",
            type: nil,
            mode: :buffer,
            remaining: 0,
            payload_length: 0,
            fragments: [],
            max_frame_length: @default_max_frame_length,
            frame_policy: nil

  @type frame :: {Frame.type_code(), binary() | :discarded}
  @type frame_policy :: (Frame.type_code(), non_neg_integer() ->
                           :buffer | :discard | {:error, term()})
  @opaque t :: %__MODULE__{
            header: binary(),
            type: nil | Frame.type_code(),
            mode: :buffer | :discard,
            remaining: non_neg_integer(),
            payload_length: non_neg_integer(),
            fragments: [binary()],
            max_frame_length: non_neg_integer(),
            frame_policy: nil | frame_policy()
          }

  @doc "Creates an empty decoder with a bounded accepted frame length."
  @spec new(keyword()) :: t()
  def new(options \\ []) do
    max_frame_length = Keyword.get(options, :max_frame_length, @default_max_frame_length)
    validate_max_frame_length!(max_frame_length)

    %__MODULE__{
      max_frame_length: max_frame_length,
      frame_policy: Keyword.get(options, :frame_policy)
    }
  end

  @doc "Changes the limit applied to subsequent frame headers."
  @spec with_max_frame_length(t(), non_neg_integer()) :: t()
  def with_max_frame_length(%__MODULE__{} = decoder, max_frame_length) do
    validate_max_frame_length!(max_frame_length)
    %{decoder | max_frame_length: max_frame_length}
  end

  @doc "Changes the header policy used for buffering, bounded discard, or rejection."
  @spec with_frame_policy(t(), frame_policy()) :: t()
  def with_frame_policy(%__MODULE__{} = decoder, frame_policy)
      when is_function(frame_policy, 2) do
    %{decoder | frame_policy: frame_policy}
  end

  @doc "Consumes a transport chunk and returns every complete frame in wire order."
  @spec push(t(), binary()) ::
          {:ok, [frame()], t()}
          | {:error, {:frame_too_large, non_neg_integer(), non_neg_integer()}}
  def push(%__MODULE__{} = decoder, chunk) when is_binary(chunk) do
    decode(decoder, chunk, [])
  end

  @doc "Checks that the byte stream ended on a frame boundary."
  @spec finish(t()) :: :ok | {:error, :unexpected_eof}
  def finish(%__MODULE__{header: "", type: nil}), do: :ok
  def finish(%__MODULE__{}), do: {:error, :unexpected_eof}

  defp decode(%__MODULE__{type: nil} = decoder, chunk, frames) do
    consume_header(decoder, chunk, frames)
  end

  defp decode(%__MODULE__{} = decoder, chunk, frames) do
    consume_payload(decoder, chunk, frames)
  end

  defp consume_header(decoder, chunk, frames) do
    needed = Frame.header_length() - byte_size(decoder.header)
    available = min(needed, byte_size(chunk))
    <<header_part::binary-size(^available), rest::binary>> = chunk
    header = decoder.header <> header_part

    if byte_size(header) == Frame.header_length() do
      {:ok, type, payload_length, ""} = Frame.decode_header(header)
      start_payload(%{decoder | header: ""}, type, payload_length, rest, frames)
    else
      {:ok, Enum.reverse(frames), %{decoder | header: header}}
    end
  end

  defp start_payload(decoder, type, payload_length, chunk, frames) do
    case frame_policy(decoder, type, payload_length) do
      :buffer -> start_frame(decoder, type, payload_length, :buffer, chunk, frames)
      :discard -> start_frame(decoder, type, payload_length, :discard, chunk, frames)
      {:error, reason} -> {:error, reason}
    end
  end

  defp start_frame(decoder, type, 0, mode, chunk, frames) do
    payload = if mode == :buffer, do: "", else: :discarded
    decode(%{decoder | type: nil, mode: :buffer}, chunk, [{type, payload} | frames])
  end

  defp start_frame(decoder, type, payload_length, mode, chunk, frames) do
    decoder = %{
      decoder
      | type: type,
        mode: mode,
        remaining: payload_length,
        payload_length: payload_length,
        fragments: []
    }

    consume_payload(decoder, chunk, frames)
  end

  defp consume_payload(decoder, "", frames),
    do: {:ok, Enum.reverse(frames), decoder}

  defp consume_payload(decoder, chunk, frames) do
    consumed = min(decoder.remaining, byte_size(chunk))
    <<fragment::binary-size(^consumed), rest::binary>> = chunk
    fragments = retain_fragment(decoder.mode, fragment, decoder.fragments)
    remaining = decoder.remaining - consumed

    if remaining == 0 do
      type = decoder.type
      payload = payload(decoder.mode, fragments, decoder.payload_length)

      decoder = %{
        decoder
        | type: nil,
          mode: :buffer,
          remaining: 0,
          payload_length: 0,
          fragments: []
      }

      decode(decoder, rest, [{type, payload} | frames])
    else
      {:ok, Enum.reverse(frames), %{decoder | remaining: remaining, fragments: fragments}}
    end
  end

  defp join_fragments([fragment], _payload_length), do: fragment

  defp join_fragments(fragments, payload_length) do
    fragments
    |> Enum.reverse()
    |> IO.iodata_to_binary()
    |> ensure_length(payload_length)
  end

  defp ensure_length(payload, expected_length) when byte_size(payload) == expected_length,
    do: payload

  defp retain_fragment(:buffer, fragment, fragments), do: [fragment | fragments]
  defp retain_fragment(:discard, _fragment, fragments), do: fragments

  defp payload(:buffer, fragments, payload_length),
    do: join_fragments(fragments, payload_length)

  defp payload(:discard, _fragments, _payload_length), do: :discarded

  defp frame_policy(%__MODULE__{frame_policy: policy}, type, payload_length)
       when is_function(policy, 2) do
    policy.(type, payload_length)
  end

  defp frame_policy(decoder, _type, payload_length) do
    if payload_length > decoder.max_frame_length do
      {:error, {:frame_too_large, payload_length, decoder.max_frame_length}}
    else
      :buffer
    end
  end

  defp validate_max_frame_length!(max_frame_length) do
    if not is_integer(max_frame_length) or max_frame_length < 0 or
         max_frame_length > 0xFFFFFFFF do
      raise ArgumentError, "max_frame_length must be an unsigned 32-bit integer"
    end
  end
end
