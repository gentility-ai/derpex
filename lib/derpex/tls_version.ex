defmodule Derpex.TLSVersion do
  @moduledoc """
  The minimum TLS version DERPEX serves and dials.

  Pinned `cmd/derper` sets `MinVersion: tls.VersionTLS12`. DERPEX defaults to
  TLS 1.3 only, which refuses a conforming TLS-1.2-only client, so
  `DERPEX_TLS_MIN_VERSION=1.2` exists to restore upstream parity. The setting
  covers both directions: the listener that serves peers and the mesh client
  that dials them.
  """

  @default "1.3"

  @doc "The minimum version DERPEX uses when the environment says nothing."
  @spec default() :: String.t()
  def default, do: @default

  @doc """
  Parses the configured minimum into the `:versions` list `:ssl` takes, treating
  an absent or empty value as the default.

  A minimum of 1.2 admits 1.3 as well; it lowers the floor rather than pinning
  the version.
  """
  @spec parse(nil | binary()) ::
          {:ok, [:"tlsv1.2" | :"tlsv1.3"]} | {:error, :invalid_tls_min_version}
  def parse(value)

  def parse(value) when value in [nil, ""], do: parse(@default)

  def parse(value) when is_binary(value) do
    case String.trim(value) do
      "1.3" -> {:ok, [:"tlsv1.3"]}
      "1.2" -> {:ok, [:"tlsv1.2", :"tlsv1.3"]}
      "" -> parse(@default)
      _other -> {:error, :invalid_tls_min_version}
    end
  end

  def parse(_value), do: {:error, :invalid_tls_min_version}

  @doc "Parses the configured minimum, raising with the accepted values."
  @spec parse!(nil | binary()) :: [:"tlsv1.2" | :"tlsv1.3"]
  def parse!(value) do
    case parse(value) do
      {:ok, versions} -> versions
      {:error, :invalid_tls_min_version} -> raise ArgumentError, message()
    end
  end

  @doc "The operator-facing description of what this setting accepts."
  @spec message() :: String.t()
  def message,
    do: ~s(DERPEX_TLS_MIN_VERSION must be "1.2" or "1.3"; it defaults to "#{@default}")
end
