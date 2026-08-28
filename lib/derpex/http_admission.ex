defmodule Derpex.HTTPAdmission do
  @moduledoc "Bounded client for the pinned DERP HTTP admission-controller contract."

  @behaviour Derpex.ClientVerifier

  require Logger

  alias Derpex.Admission.Request
  alias Derpex.HTTPClient
  alias Derpex.JSON

  @default_timeout_ms 5_000
  @default_max_response_bytes 4_096

  @type options :: [
          url: URI.t() | binary(),
          fail_open: boolean(),
          timeout_ms: pos_integer(),
          max_response_bytes: pos_integer(),
          tls_options: keyword()
        ]

  @impl true
  def verify(%Request{node_key: node_key, source_ip: source_ip}, options) do
    admit(node_key, source_ip, options)
  end

  @doc "Posts the pinned admission request and returns the controller decision."
  @spec admit(binary(), :inet.ip_address(), options()) :: :ok | {:error, term()}
  def admit(<<node_key::binary-size(32)>>, source_ip, options) when is_list(options) do
    with {:ok, uri} <- fetch_url(options),
         {:ok, source} <- format_ip(source_ip) do
      body =
        JSON.encode_object([
          {"NodePublic", "nodekey:" <> Base.encode16(node_key, case: :lower)},
          {"Source", source}
        ])

      http_options = [
        timeout_ms: Keyword.get(options, :timeout_ms, @default_timeout_ms),
        max_response_bytes:
          Keyword.get(options, :max_response_bytes, @default_max_response_bytes),
        tls_options: Keyword.get(options, :tls_options, [])
      ]

      case HTTPClient.request(uri, request(uri, body), http_options) do
        {:ok, {200, _headers, response_body}} -> decode_decision(response_body)
        {:ok, {status, _headers, _response_body}} -> {:error, {:admission_status, status}}
        {:error, reason} -> handle_request_error(reason, options)
      end
    end
  end

  @doc "Parses an absolute HTTP(S) admission URL."
  @spec parse_url(binary()) :: {:ok, URI.t()} | {:error, :invalid_admission_url}
  def parse_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host} = uri
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _invalid ->
        {:error, :invalid_admission_url}
    end
  rescue
    ArgumentError -> {:error, :invalid_admission_url}
  end

  defp fetch_url(options) do
    case Keyword.fetch(options, :url) do
      {:ok, %URI{} = uri} -> parse_url(URI.to_string(uri))
      {:ok, url} when is_binary(url) -> parse_url(url)
      _missing_or_invalid -> {:error, :invalid_admission_url}
    end
  end

  defp request(uri, body) do
    [
      "POST ",
      request_target(uri),
      " HTTP/1.1\r\nHost: ",
      host_header(uri),
      "\r\nContent-Length: ",
      Integer.to_string(byte_size(body)),
      "\r\n",
      authorization_header(uri),
      "Connection: close\r\n\r\n",
      body
    ]
  end

  defp request_target(uri) do
    path = if uri.path in [nil, ""], do: "/", else: uri.path
    if is_binary(uri.query), do: path <> "?" <> uri.query, else: path
  end

  defp host_header(%URI{host: host, scheme: scheme, port: port}) do
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host

    if port in [nil, URI.default_port(scheme)],
      do: host,
      else: host <> ":" <> Integer.to_string(port)
  end

  defp authorization_header(%URI{userinfo: nil}), do: []

  defp authorization_header(%URI{userinfo: userinfo}) do
    ["Authorization: Basic ", Base.encode64(URI.decode(userinfo)), "\r\n"]
  end

  defp decode_decision(body) do
    with {:ok, fields} <- JSON.decode_object(body),
         {:ok, allow?} <- allow_field(fields) do
      if allow?, do: :ok, else: {:error, :admission_denied}
    else
      {:error, reason} -> {:error, {:invalid_admission_response, reason}}
    end
  end

  defp allow_field(fields) do
    Enum.reduce_while(fields, {:ok, false}, fn
      {"Allow", value}, _current when is_boolean(value) -> {:cont, {:ok, value}}
      {"Allow", _invalid}, _current -> {:halt, {:error, :invalid_allow}}
      {_unknown, _value}, current -> {:cont, current}
    end)
  end

  defp handle_request_error(reason, options) do
    cond do
      not unavailable?(reason) ->
        {:error, {:invalid_admission_response, response_error(reason)}}

      Keyword.get(options, :fail_open, true) ->
        Logger.warning("DERP admission controller is unavailable; allowing client")
        :ok

      true ->
        {:error, {:admission_unavailable, reason}}
    end
  end

  defp unavailable?({phase, _reason}) when phase in [:connect, :send], do: true

  defp unavailable?({:response_head, reason})
       when reason in [:closed, :timeout, :econnreset],
       do: true

  defp unavailable?(_reason), do: false

  defp response_error({_phase, reason}), do: reason
  defp response_error(reason), do: reason

  defp format_ip(ip) when tuple_size(ip) in [4, 8] do
    case :inet.ntoa(ip) do
      address when is_list(address) -> {:ok, List.to_string(address)}
      {:error, _reason} -> {:error, :invalid_source_ip}
    end
  rescue
    ArgumentError -> {:error, :invalid_source_ip}
  end

  defp format_ip(_invalid), do: {:error, :invalid_source_ip}
end
