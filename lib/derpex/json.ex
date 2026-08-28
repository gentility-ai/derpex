defmodule Derpex.JSON do
  @moduledoc false

  @spec decode_object(binary()) :: {:ok, [{binary(), term()}]} | {:error, term()}
  def decode_object(binary) when is_binary(binary) do
    decoders = %{object_finish: &finish_object/2}

    case :json.decode(binary, nil, decoders) do
      {{:object, fields}, nil, rest} ->
        if json_whitespace?(rest), do: {:ok, fields}, else: {:error, :trailing_data}

      {_other, nil, _rest} ->
        {:error, :expected_object}
    end
  catch
    :error, reason -> {:error, reason}
  end

  @spec encode_object([{binary(), term()}]) :: binary()
  def encode_object(fields) when is_list(fields) do
    fields
    |> Enum.map(fn {key, value} -> [:json.encode_binary(key), ?:, :json.encode(value)] end)
    |> Enum.intersperse(?,)
    |> then(&[?{, &1, ?}])
    |> IO.iodata_to_binary()
  end

  defp json_whitespace?(<<>>), do: true

  defp json_whitespace?(<<byte, rest::binary>>) when byte in [0x20, 0x09, 0x0A, 0x0D],
    do: json_whitespace?(rest)

  defp json_whitespace?(_rest), do: false

  defp finish_object(fields, previous_accumulator) do
    {{:object, Enum.reverse(fields)}, previous_accumulator}
  end
end
