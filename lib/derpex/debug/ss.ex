defmodule Derpex.Debug.SS do
  @moduledoc "Parser for the Linux `ss -i -H -t` traffic-counter shape."

  @type endpoint :: {:inet.ip_address(), 1..65_535}
  @type counters :: %{sent: non_neg_integer(), received: non_neg_integer()}

  @doc "Parses alternating connection and TCP-info lines, skipping malformed entries."
  @spec parse(binary()) :: %{optional(endpoint()) => counters()}
  def parse(output) when is_binary(output) do
    output
    |> String.split("\n", trim: false)
    |> Enum.chunk_every(2, 2, :discard)
    |> Enum.reduce(%{}, fn [connection, statistics], parsed ->
      with {:ok, endpoint} <- parse_endpoint(connection),
           counters <- parse_counters(statistics) do
        Map.put(parsed, endpoint, counters)
      else
        _malformed -> parsed
      end
    end)
  end

  defp parse_endpoint(connection) do
    case String.split(String.trim(connection)) do
      fields when length(fields) >= 5 -> fields |> Enum.at(4) |> parse_address_port()
      _short -> :error
    end
  end

  defp parse_address_port(value) do
    with {separator, 1} <- last_colon(value),
         <<address::binary-size(^separator), ?:, port_text::binary>> <- value,
         {port, ""} when port in 1..65_535 <- Integer.parse(port_text),
         {:ok, ip} <-
           address |> trim_ipv6_brackets() |> String.to_charlist() |> :inet.parse_address() do
      {:ok, {ip, port}}
    else
      _invalid -> :error
    end
  end

  defp last_colon(value) do
    case :binary.matches(value, ":") do
      [] -> :nomatch
      matches -> List.last(matches)
    end
  end

  defp trim_ipv6_brackets(<<?[, rest::binary>>) do
    address_size = byte_size(rest) - 1

    case rest do
      <<address::binary-size(^address_size), ?]>> -> address
      _not_bracketed -> rest
    end
  end

  defp trim_ipv6_brackets(address), do: address

  defp parse_counters(statistics) do
    statistics
    |> String.split()
    |> Enum.reduce(%{sent: 0, received: 0}, fn token, counters ->
      cond do
        String.starts_with?(token, "bytes_sent:") ->
          %{counters | sent: parse_counter(token)}

        String.starts_with?(token, "bytes_received:") ->
          %{counters | received: parse_counter(token)}

        true ->
          counters
      end
    end)
  end

  defp parse_counter(token) do
    case token |> String.split(":", parts: 2) |> List.last() |> Integer.parse() do
      {counter, ""} when counter >= 0 -> counter
      _invalid -> 0
    end
  end
end
