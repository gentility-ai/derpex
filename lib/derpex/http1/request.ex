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

  @doc "Returns the normalized request path without a query string."
  @spec path(t()) :: binary()
  def path(%__MODULE__{target: target}) do
    {path, _query} = path_and_query(target)
    path
  end

  @doc "Returns a decoded query parameter, matching Go URL.Query().Get."
  @spec query_param(t(), binary()) :: binary() | nil
  def query_param(%__MODULE__{target: target}, name) do
    case path_and_query(target) do
      {_path, query} when is_binary(query) -> query |> URI.decode_query() |> Map.get(name)
      {_path, nil} -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp path_and_query(target) do
    case URI.parse(target) do
      %URI{scheme: scheme, host: host, path: path, query: query}
      when scheme in ["http", "https"] and is_binary(host) ->
        {if(path in [nil, ""], do: "/", else: path), query}

      _origin_or_authority_form ->
        case :binary.split(target, "?") do
          [path, query] -> {path, query}
          [path] -> {path, nil}
        end
    end
  end
end
