defmodule Derpex.HTTP1.Parser do
  @moduledoc "Incremental, bounded HTTP/1 request-head parser."

  alias Derpex.HTTP1.Request

  @default_max_header_bytes 1 * 1_024 * 1_024
  @default_max_request_line_bytes 8 * 1_024
  @default_max_headers 100

  defstruct buffer: "",
            max_header_bytes: @default_max_header_bytes,
            max_request_line_bytes: @default_max_request_line_bytes,
            max_headers: @default_max_headers

  @opaque t :: %__MODULE__{
            buffer: binary(),
            max_header_bytes: pos_integer(),
            max_request_line_bytes: pos_integer(),
            max_headers: pos_integer()
          }

  @doc "Creates an empty request parser."
  @spec new(keyword()) :: t()
  def new(options \\ []) do
    %__MODULE__{
      max_header_bytes: positive_option!(options, :max_header_bytes, @default_max_header_bytes),
      max_request_line_bytes:
        positive_option!(options, :max_request_line_bytes, @default_max_request_line_bytes),
      max_headers: positive_option!(options, :max_headers, @default_max_headers)
    }
  end

  @doc "Consumes bytes until one request head is complete, returning all read-ahead bytes."
  @spec push(t(), binary()) ::
          {:more, t()} | {:ok, Request.t(), binary(), t()} | {:error, atom()}
  def push(%__MODULE__{} = parser, chunk) when is_binary(chunk) do
    buffer = parser.buffer <> chunk

    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} when head_length + 4 <= parser.max_header_bytes ->
        <<head::binary-size(^head_length), "\r\n\r\n", read_ahead::binary>> = buffer

        case parse_head(parser, head) do
          {:ok, request} -> {:ok, request, read_ahead, %{parser | buffer: ""}}
          {:error, reason} -> {:error, reason}
        end

      {_head_length, 4} ->
        {:error, :headers_too_large}

      :nomatch when byte_size(buffer) >= parser.max_header_bytes ->
        {:error, :headers_too_large}

      :nomatch ->
        {:more, %{parser | buffer: buffer}}
    end
  end

  defp parse_head(parser, head) do
    case :binary.split(head, "\r\n", [:global]) do
      [request_line | header_lines] ->
        with :ok <- validate_request_line_length(parser, request_line),
             {:ok, method, target, version} <- parse_request_line(request_line),
             {:ok, headers} <- parse_headers(parser, header_lines) do
          {:ok, %Request{method: method, target: target, version: version, headers: headers}}
        end

      [] ->
        {:error, :invalid_request_line}
    end
  end

  defp validate_request_line_length(parser, request_line) do
    if byte_size(request_line) <= parser.max_request_line_bytes,
      do: :ok,
      else: {:error, :request_line_too_large}
  end

  defp parse_request_line(request_line) do
    case :binary.split(request_line, " ", [:global]) do
      [method, target, version] when method != "" and target != "" ->
        if valid_token?(method) and version in ["HTTP/1.0", "HTTP/1.1"] do
          {:ok, method, target, version}
        else
          {:error, :invalid_request_line}
        end

      _parts ->
        {:error, :invalid_request_line}
    end
  end

  defp parse_headers(parser, header_lines) when length(header_lines) <= parser.max_headers do
    Enum.reduce_while(header_lines, {:ok, []}, fn line, {:ok, headers} ->
      case parse_header(line) do
        {:ok, header} -> {:cont, {:ok, [header | headers]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, headers} -> {:ok, Enum.reverse(headers)}
      {:error, _reason} = error -> error
    end
  end

  defp parse_headers(_parser, _header_lines), do: {:error, :too_many_headers}

  defp parse_header(line) do
    case :binary.match(line, ":") do
      {name_length, 1} when name_length > 0 ->
        <<name::binary-size(^name_length), ?:, value::binary>> = line

        if valid_token?(name) and valid_header_value?(value) do
          {:ok, {String.downcase(name, :ascii), trim_optional_whitespace(value)}}
        else
          {:error, :invalid_header}
        end

      _other ->
        {:error, :invalid_header}
    end
  end

  defp valid_token?(token), do: token != "" and token_bytes?(token)
  defp token_bytes?(<<>>), do: true

  defp token_bytes?(<<byte, rest::binary>>)
       when byte in ?0..?9 or byte in ?A..?Z or byte in ?a..?z or
              byte in ~c"!#$%&'*+-.^_`|~" do
    token_bytes?(rest)
  end

  defp token_bytes?(_token), do: false

  defp valid_header_value?(value), do: header_value_bytes?(value)
  defp header_value_bytes?(<<>>), do: true

  defp header_value_bytes?(<<byte, rest::binary>>)
       when byte == 0x09 or byte in 0x20..0x7E or byte in 0x80..0xFF do
    header_value_bytes?(rest)
  end

  defp header_value_bytes?(_value), do: false

  defp trim_optional_whitespace(value) do
    value
    |> trim_leading_whitespace()
    |> trim_trailing_whitespace()
  end

  defp trim_leading_whitespace(<<byte, rest::binary>>) when byte in [0x20, 0x09],
    do: trim_leading_whitespace(rest)

  defp trim_leading_whitespace(value), do: value

  defp trim_trailing_whitespace(""), do: ""

  defp trim_trailing_whitespace(value) do
    rest_size = byte_size(value) - 1

    case value do
      <<rest::binary-size(^rest_size), byte>> when byte in [0x20, 0x09] ->
        trim_trailing_whitespace(rest)

      _value ->
        value
    end
  end

  defp positive_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value > 0 -> value
      _value -> raise ArgumentError, "#{key} must be a positive integer"
    end
  end
end
