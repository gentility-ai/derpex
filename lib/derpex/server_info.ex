# This module implements behavior from Tailscale's DERP ServerInfo type.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ServerInfo do
  @moduledoc "Information a DERP server sends after authenticating a client."

  alias Derpex.JSON

  @min_integer -9_223_372_036_854_775_808
  @max_integer 9_223_372_036_854_775_807

  defstruct version: 0,
            token_bucket_bytes_per_second: 0,
            token_bucket_bytes_burst: 0

  @type t :: %__MODULE__{
          version: integer(),
          token_bucket_bytes_per_second: integer(),
          token_bucket_bytes_burst: integer()
        }

  @doc "Decodes Go-compatible ServerInfo JSON."
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(json) do
    with {:ok, fields} <- JSON.decode_object(json) do
      decode_fields(fields, %__MODULE__{})
    end
  end

  @doc "Encodes ServerInfo with Go's field names, order, and omission rules."
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = info) do
    []
    |> append_if(info.version != 0, {"version", info.version})
    |> append_if(info.token_bucket_bytes_per_second != 0, {
      "TokenBucketBytesPerSecond",
      info.token_bucket_bytes_per_second
    })
    |> append_if(info.token_bucket_bytes_burst != 0, {
      "TokenBucketBytesBurst",
      info.token_bucket_bytes_burst
    })
    |> JSON.encode_object()
  end

  defp decode_fields([], info), do: {:ok, info}

  defp decode_fields([{key, value} | rest], info) do
    case String.downcase(key, :ascii) do
      "version" ->
        decode_integer_field(:version, value, rest, info)

      "tokenbucketbytespersecond" ->
        decode_integer_field(:token_bucket_bytes_per_second, value, rest, info)

      "tokenbucketbytesburst" ->
        decode_integer_field(:token_bucket_bytes_burst, value, rest, info)

      _unknown ->
        decode_fields(rest, info)
    end
  end

  defp decode_integer_field(field, value, rest, info)
       when is_integer(value) and value >= @min_integer and value <= @max_integer do
    decode_fields(rest, Map.put(info, field, value))
  end

  defp decode_integer_field(field, _value, _rest, _info), do: {:error, {:invalid_field, field}}

  defp append_if(fields, true, field), do: fields ++ [field]
  defp append_if(fields, false, _field), do: fields
end
