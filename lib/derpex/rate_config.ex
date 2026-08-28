defmodule Derpex.RateConfig do
  @moduledoc "Go-compatible per-client receive-rate configuration."

  alias Derpex.JSON

  @minimum_burst 65_536 + 32
  @maximum_unsigned_64 0xFFFFFFFFFFFFFFFF

  defstruct per_client_rate_limit_bytes_per_second: 0,
            per_client_rate_burst_bytes: 0

  @type t :: %__MODULE__{
          per_client_rate_limit_bytes_per_second: non_neg_integer(),
          per_client_rate_burst_bytes: non_neg_integer()
        }

  @doc "The minimum bucket size required to admit one maximum SendPacket body."
  @spec minimum_burst() :: pos_integer()
  def minimum_burst, do: @minimum_burst

  @doc "Loads the upstream JSON field names from a non-empty path."
  @spec load(binary()) :: {:ok, t()} | {:error, term()}
  def load(""), do: {:error, :empty_rate_config_path}

  def load(path) when is_binary(path) do
    with {:ok, contents} <- File.read(path),
         {:ok, fields} <- JSON.decode_object(contents) do
      decode_fields(fields, %__MODULE__{})
    end
  end

  @doc "Applies upstream disabling and minimum-burst normalization rules."
  @spec normalize(t()) :: t()
  def normalize(%__MODULE__{per_client_rate_limit_bytes_per_second: 0}),
    do: %__MODULE__{}

  def normalize(%__MODULE__{} = config) do
    %{
      config
      | per_client_rate_burst_bytes: max(config.per_client_rate_burst_bytes, @minimum_burst)
    }
  end

  defp decode_fields([], config), do: {:ok, config}

  defp decode_fields([{name, value} | rest], config) do
    case String.downcase(name, :ascii) do
      "perclientratelimitbytespersec" ->
        put_unsigned(rest, config, :per_client_rate_limit_bytes_per_second, value)

      "perclientrateburstbytes" ->
        put_unsigned(rest, config, :per_client_rate_burst_bytes, value)

      _unknown ->
        decode_fields(rest, config)
    end
  end

  defp put_unsigned(rest, config, field, value)
       when is_integer(value) and value in 0..@maximum_unsigned_64 do
    decode_fields(rest, Map.put(config, field, value))
  end

  defp put_unsigned(_rest, _config, field, _value), do: {:error, {:invalid_field, field}}
end
