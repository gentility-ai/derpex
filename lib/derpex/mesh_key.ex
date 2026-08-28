defmodule Derpex.MeshKey do
  @moduledoc "Parsing and constant-time comparison for DERP mesh credentials."

  @type t :: <<_::256>>

  @doc "Parses a whitespace-trimmed 64-digit hexadecimal mesh key."
  @spec parse(binary()) :: {:ok, t()} | {:error, :invalid_mesh_key}
  def parse(value) when is_binary(value) do
    value = String.trim(value)

    with 64 <- byte_size(value),
         {:ok, <<key::binary-size(32)>>} <- Base.decode16(value, case: :mixed) do
      {:ok, key}
    else
      _invalid -> {:error, :invalid_mesh_key}
    end
  end

  @doc "Returns true only when the configured and advertised keys match in constant time."
  @spec trusted?(nil | t(), nil | t()) :: boolean()
  def trusted?(<<configured::binary-size(32)>>, <<advertised::binary-size(32)>>) do
    :crypto.hash_equals(configured, advertised)
  end

  def trusted?(_configured, _advertised), do: false
end
