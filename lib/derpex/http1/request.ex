defmodule Derpex.HTTP1.Request do
  @moduledoc "A bounded, parsed HTTP/1 request head."

  defstruct [:method, :target, :version, headers: []]

  @type t :: %__MODULE__{
          method: binary(),
          target: binary(),
          version: binary(),
          headers: [{binary(), binary()}]
        }

  @doc "Returns the first value of a case-insensitive header, matching Go Header.Get."
  @spec header(t(), binary()) :: binary() | nil
  def header(%__MODULE__{headers: headers}, name) do
    name = String.downcase(name, :ascii)

    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  @doc "Returns the origin-form path without a query string."
  @spec path(t()) :: binary()
  def path(%__MODULE__{target: target}) do
    case :binary.split(target, "?", [:global]) do
      [path | _query] -> path
      [] -> target
    end
  end

  @doc "Returns a decoded query parameter, matching Go URL.Query().Get."
  @spec query_param(t(), binary()) :: binary() | nil
  def query_param(%__MODULE__{target: target}, name) do
    case :binary.split(target, "?", [:global]) do
      [_path, query | _rest] -> query |> URI.decode_query() |> Map.get(name)
      [_path] -> nil
    end
  rescue
    ArgumentError -> nil
  end
end
