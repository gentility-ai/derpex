# This module implements behavior from Tailscale's DERP ClientInfo type.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ClientInfo do
  @moduledoc "Information a DERP client authenticates during its handshake."

  alias Derpex.JSON

  @max_app_name_length 32
  @min_integer -9_223_372_036_854_775_808
  @max_integer 9_223_372_036_854_775_807

  # The peer's mesh key authenticates it to this relay. It has no business in a
  # crash report, a log line, or anything else that renders process state.
  @derive {Inspect, except: [:mesh_key]}
  defstruct mesh_key: nil,
            version: 0,
            can_ack_pings: false,
            is_prober: false,
            app_name: ""

  @type t :: %__MODULE__{
          mesh_key: nil | <<_::256>>,
          version: integer(),
          can_ack_pings: boolean(),
          is_prober: boolean(),
          app_name: binary()
        }

  @doc "Decodes Go-compatible ClientInfo JSON, including case-insensitive field names."
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(json) do
    with {:ok, fields} <- JSON.decode_object(json),
         {:ok, info} <- decode_fields(fields, %__MODULE__{}),
         true <- valid_app_name?(info.app_name) do
      {:ok, info}
    else
      false -> {:error, :invalid_app_name}
      {:error, _reason} = error -> error
    end
  end

  @doc "Encodes ClientInfo with Go's field names, order, and omission rules."
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{} = info) do
    []
    |> append_mesh_key(info.mesh_key)
    |> append_if(info.version != 0, {"version", info.version})
    |> Kernel.++([{"CanAckPings", info.can_ack_pings}])
    |> append_if(info.is_prober, {"IsProber", info.is_prober})
    |> append_if(info.app_name != "", {"AppName", info.app_name})
    |> JSON.encode_object()
  end

  @doc "Returns true for at most 32 bytes of printable ASCII, including empty."
  @spec valid_app_name?(binary()) :: boolean()
  def valid_app_name?(name) when is_binary(name) and byte_size(name) <= @max_app_name_length do
    printable_ascii?(name)
  end

  def valid_app_name?(_name), do: false

  defp decode_fields([], info), do: {:ok, info}

  defp decode_fields([{key, value} | rest], info) do
    case String.downcase(key, :ascii) do
      "meshkey" -> decode_mesh_field(value, rest, info)
      "version" -> decode_integer_field(:version, value, rest, info)
      "canackpings" -> decode_boolean_field(:can_ack_pings, value, rest, info)
      "isprober" -> decode_boolean_field(:is_prober, value, rest, info)
      "appname" -> decode_string_field(:app_name, value, rest, info)
      _unknown -> decode_fields(rest, info)
    end
  end

  defp decode_mesh_field(value, rest, info) when is_binary(value) do
    case decode_mesh_key(value) do
      {:ok, mesh_key} -> decode_fields(rest, %{info | mesh_key: mesh_key})
      :error -> {:error, :invalid_mesh_key}
    end
  end

  defp decode_mesh_field(_value, _rest, _info), do: {:error, :invalid_mesh_key}

  defp decode_integer_field(field, value, rest, info)
       when is_integer(value) and value >= @min_integer and value <= @max_integer do
    decode_fields(rest, Map.put(info, field, value))
  end

  defp decode_integer_field(field, _value, _rest, _info), do: {:error, {:invalid_field, field}}

  defp decode_boolean_field(field, value, rest, info) when is_boolean(value) do
    decode_fields(rest, Map.put(info, field, value))
  end

  defp decode_boolean_field(field, _value, _rest, _info), do: {:error, {:invalid_field, field}}

  defp decode_string_field(field, value, rest, info) when is_binary(value) do
    decode_fields(rest, Map.put(info, field, value))
  end

  defp decode_string_field(field, _value, _rest, _info), do: {:error, {:invalid_field, field}}

  defp decode_mesh_key(value) when byte_size(value) == 64 do
    case Base.decode16(value, case: :mixed) do
      {:ok, <<_mesh_key::binary-size(32)>> = mesh_key} -> {:ok, mesh_key}
      :error -> :error
    end
  end

  defp decode_mesh_key(_value), do: :error
  defp encode_mesh_key(<<mesh_key::binary-size(32)>>), do: Base.encode16(mesh_key, case: :lower)

  defp printable_ascii?(<<>>), do: true

  defp printable_ascii?(<<byte, rest::binary>>) when byte in 0x20..0x7E,
    do: printable_ascii?(rest)

  defp printable_ascii?(_name), do: false

  defp append_if(fields, true, field), do: fields ++ [field]
  defp append_if(fields, false, _field), do: fields

  defp append_mesh_key(fields, nil), do: fields

  defp append_mesh_key(fields, <<mesh_key::binary-size(32)>>) do
    fields ++ [{"meshKey", encode_mesh_key(mesh_key)}]
  end
end
