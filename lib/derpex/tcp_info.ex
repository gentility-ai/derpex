defmodule Derpex.TCPInfo do
  @moduledoc "Bounded Linux `TCP_INFO` access for connection RTT sampling."

  alias ThousandIsland.Socket

  @ipproto_tcp 6
  @tcp_info 11
  @tcp_info_size 0x118
  @rtt_offset 68

  @doc "Reads Linux's smoothed TCP RTT in microseconds."
  @spec rtt_microseconds(Socket.t(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def rtt_microseconds(socket, options \\ []) do
    case Keyword.get(options, :reader) do
      reader when is_function(reader, 1) -> reader.(socket)
      nil -> platform_rtt(socket)
    end
  rescue
    exception -> {:error, Exception.message(exception)}
  catch
    kind, reason -> {:error, Exception.format_banner(kind, reason)}
  end

  @doc false
  @spec supported?(keyword()) :: boolean()
  def supported?(options \\ []) do
    is_function(Keyword.get(options, :reader), 1) or :os.type() == {:unix, :linux}
  end

  @doc false
  @spec decode(binary()) :: {:ok, non_neg_integer()} | {:error, :invalid_tcp_info}
  def decode(info) when byte_size(info) >= @rtt_offset + 4 do
    <<_prefix::binary-size(@rtt_offset), rtt::32-native, _rest::binary>> = info
    {:ok, rtt}
  end

  def decode(_info), do: {:error, :invalid_tcp_info}

  defp platform_rtt(socket) do
    case :os.type() do
      {:unix, :linux} -> get_tcp_info(socket)
      _other -> {:error, :unsupported}
    end
  end

  defp get_tcp_info(socket) do
    option = {:raw, @ipproto_tcp, @tcp_info, @tcp_info_size}

    case Socket.getopts(socket, [option]) do
      {:ok, [{:raw, @ipproto_tcp, @tcp_info, info}]} -> decode(info)
      {:ok, []} -> {:error, :unsupported}
      {:error, reason} -> {:error, reason}
      _unexpected -> {:error, :invalid_tcp_info}
    end
  end
end
