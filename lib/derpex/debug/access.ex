defmodule Derpex.Debug.Access do
  @moduledoc """
  Authorization rules for the pinned protected debug surface.

  Loopback and the Tailscale IPv6 ULA (`fd7a:115c:a1e0::/48`) are always
  granted: neither is reachable from the public internet. The Tailscale IPv4
  CGNAT range (`100.64.0.0/10`) is **not** granted by default, because a relay
  on a public port can see a carrier-NAT source address that belongs to no
  tailnet. Set `allow_tailscale_cgnat: true` (from
  `DERPEX_DEBUG_ALLOW_TAILSCALE_CGNAT=1`) on a relay whose only CGNAT peers are
  tailnet nodes.
  """

  import Bitwise

  alias Derpex.HTTP1.Request
  alias Derpex.Operations

  @type prefix :: {:inet.ip_address(), 0..128}

  @doc "Authorizes bearer, debug-key, or approved source-address access."
  @spec authorize(Request.t(), keyword(), keyword()) :: :authorized | :unauthorized
  def authorize(%Request{} = request, options, operations \\ []) do
    cond do
      Operations.authorize(request, operations) == :authorized -> :authorized
      debug_key_authorized?(request, options) -> :authorized
      Request.header(request, "x-forwarded-for") not in [nil, ""] -> :unauthorized
      source_authorized?(Keyword.get(options, :remote_ip), options) -> :authorized
      true -> :unauthorized
    end
  end

  @doc "Parses the comma-separated upstream trusted-CIDR setting."
  @spec parse_trusted_cidrs(nil | binary()) :: {:ok, [prefix()]} | {:error, term()}
  def parse_trusted_cidrs(value) when value in [nil, ""], do: {:ok, []}

  def parse_trusted_cidrs(value) when is_binary(value) do
    value
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.reduce_while({:ok, []}, fn text, {:ok, prefixes} ->
      case parse_prefix(text) do
        {:ok, prefix} -> {:cont, {:ok, [prefix | prefixes]}}
        {:error, reason} -> {:halt, {:error, {text, reason}}}
      end
    end)
    |> case do
      {:ok, prefixes} -> {:ok, Enum.reverse(prefixes)}
      {:error, _reason} = error -> error
    end
  end

  defp debug_key_authorized?(%Request{method: "GET"} = request, options) do
    with key when is_binary(key) and key != "" <- Request.query_param(request, "debugkey"),
         path when is_binary(path) and path != "" <- Keyword.get(options, :key_path),
         {:ok, expected} <- File.read(path) do
      constant_time_equal?(key, String.trim(expected))
    else
      _missing_or_unreadable -> false
    end
  end

  defp debug_key_authorized?(_request, _options), do: false

  defp source_authorized?(ip, options) do
    valid_ip?(ip) and
      (loopback?(ip) or tailscale_ip?(ip, options) or allowed_ip?(ip, options) or
         trusted_cidr?(ip, Keyword.get(options, :trusted_cidrs, [])))
  end

  defp allowed_ip?(ip, options) do
    case Keyword.get(options, :allow_ip) do
      value when is_binary(value) -> format_ip(ip) == value
      _missing -> false
    end
  end

  defp trusted_cidr?(ip, prefixes), do: Enum.any?(prefixes, &contains?(&1, ip))

  defp contains?({network, prefix}, ip) when tuple_size(network) == tuple_size(ip) do
    bits = if tuple_size(ip) == 4, do: 32, else: 128
    shift = bits - prefix
    ip_integer(network) >>> shift == ip_integer(ip) >>> shift
  end

  defp contains?(_prefix, _ip), do: false

  defp parse_prefix(text) do
    with [address_text, prefix_text] <- String.split(text, "/", parts: 2),
         {:ok, address} <- address_text |> String.to_charlist() |> :inet.parse_address(),
         {prefix, ""} <- Integer.parse(prefix_text),
         true <- valid_prefix?(address, prefix) do
      {:ok, {address, prefix}}
    else
      _invalid -> {:error, :invalid_cidr}
    end
  end

  defp valid_prefix?(address, prefix) when tuple_size(address) == 4, do: prefix in 0..32
  defp valid_prefix?(address, prefix) when tuple_size(address) == 8, do: prefix in 0..128

  defp loopback?({127, _b, _c, _d}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback?(_ip), do: false

  defp tailscale_ip?({0xFD7A, 0x115C, 0xA1E0, _d, _e, _f, _g, _h}, _options), do: true

  defp tailscale_ip?({100, second, _c, _d}, options) when second in 64..127,
    do: Keyword.get(options, :allow_tailscale_cgnat, false) == true

  defp tailscale_ip?(_ip, _options), do: false

  defp valid_ip?(ip), do: :inet.is_ip_address(ip)

  defp format_ip(ip), do: ip |> :inet.ntoa() |> List.to_string()

  defp ip_integer({a, b, c, d}), do: <<a, b, c, d>> |> :binary.decode_unsigned()

  defp ip_integer({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    |> :binary.decode_unsigned()
  end

  defp constant_time_equal?(left, right) do
    byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)
  end
end
