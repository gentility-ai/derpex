defmodule Derpex.LocalAPI do
  @moduledoc """
  Minimal bounded client for tailscaled's node-key WhoIs LocalAPI.

  This intentionally implements only the request needed by DERP client
  verification and always connects directly to a Unix-domain socket.
  """

  @behaviour Derpex.ClientVerifier

  alias Derpex.Admission.Request
  alias Derpex.HTTPClient
  alias Derpex.JSON

  @local_api_host "local-tailscaled.sock"
  @capability_version 145
  @default_timeout_ms 5_000
  @default_max_response_bytes 1_048_576

  @type options :: [
          socket_path: Path.t(),
          timeout_ms: pos_integer(),
          max_response_bytes: pos_integer()
        ]

  @impl true
  def verify(%Request{node_key: node_key}, options) do
    whois_node_key(node_key, options)
  end

  @doc "Checks whether tailscaled recognizes a raw 32-byte node public key."
  @spec whois_node_key(binary(), options()) :: :ok | {:error, term()}
  def whois_node_key(<<node_key::binary-size(32)>>, options \\ []) when is_list(options) do
    socket_path = Keyword.get(options, :socket_path, default_socket_path())

    if is_binary(socket_path) and socket_path != "" do
      http_options = [
        timeout_ms: Keyword.get(options, :timeout_ms, @default_timeout_ms),
        max_response_bytes: Keyword.get(options, :max_response_bytes, @default_max_response_bytes)
      ]

      case HTTPClient.request({:unix, socket_path}, request(node_key), http_options) do
        {:ok, {status, _headers, body}} -> interpret_response(status, body)
        {:error, reason} -> {:error, normalize_transport_error(reason)}
      end
    else
      {:error, :invalid_socket_path}
    end
  end

  @doc "Returns the pinned platform default used by tailscaled."
  @spec default_socket_path({:unix, atom()} | term()) :: Path.t()
  def default_socket_path(os_type \\ :os.type())
  def default_socket_path({:unix, :darwin}), do: "/var/run/tailscaled.socket"
  def default_socket_path(_os_type), do: "/var/run/tailscale/tailscaled.sock"

  defp request(node_key) do
    encoded_key =
      node_key
      |> Base.encode16(case: :lower)
      |> then(&URI.encode_www_form("nodekey:" <> &1))

    [
      "GET /localapi/v0/whois?addr=",
      encoded_key,
      " HTTP/1.1\r\n",
      "Host: ",
      @local_api_host,
      "\r\n",
      "Tailscale-Cap: ",
      Integer.to_string(@capability_version),
      "\r\n",
      "Connection: close\r\n\r\n"
    ]
  end

  defp interpret_response(200, body) do
    case JSON.decode_object(body) do
      {:ok, _fields} -> :ok
      {:error, reason} -> {:error, {:invalid_localapi_json, reason}}
    end
  end

  defp interpret_response(404, _body), do: {:error, :peer_not_found}

  defp interpret_response(status, body) do
    if String.contains?(body, "invalid 'addr' parameter") do
      {:error, :tailscaled_too_old}
    else
      {:error, {:localapi_status, status}}
    end
  end

  defp normalize_transport_error(reason)
       when reason in [:timeout, :closed, :econnrefused, :enoent],
       do: {:localapi_unavailable, reason}

  defp normalize_transport_error({_phase, reason}), do: normalize_transport_error(reason)

  defp normalize_transport_error(reason), do: {:invalid_localapi_response, reason}
end
