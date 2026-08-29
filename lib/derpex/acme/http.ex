defmodule Derpex.ACME.HTTP do
  @moduledoc """
  The ACME transport: one GET for the directory, POST for everything else.

  RFC 8555 sends every authenticated request as a JWS POST with content type
  `application/jose+json`, including its authenticated GETs, which carry an
  empty payload. Responses are read through `Derpex.HTTPClient` so an ACME
  server cannot hand a DERP relay an unbounded body.
  """

  alias Derpex.HTTPClient
  alias Derpex.JSON

  @content_type "application/jose+json"
  @user_agent "derpex"
  @max_response_bytes 1_048_576
  @timeout_ms 30_000

  @type response :: %{status: 100..999, headers: [{binary(), binary()}], body: binary()}

  @doc "Performs the directory GET."
  @spec get(binary(), keyword()) :: {:ok, response()} | {:error, term()}
  def get(url, options \\ []), do: send_request(url, options, &get_request/2)

  @doc "Performs one JWS POST."
  @spec post(binary(), iodata(), keyword()) :: {:ok, response()} | {:error, term()}
  def post(url, body, options \\ []) do
    body = IO.iodata_to_binary(body)
    send_request(url, options, &post_request(&1, &2, body))
  end

  @doc "Returns a response header, case-insensitively."
  @spec header(response(), binary()) :: binary() | nil
  def header(%{headers: headers}, name), do: HTTPClient.header(headers, name)

  @doc "Returns one member of a decoded JSON object, or nil."
  @spec field([{binary(), term()}], binary()) :: term() | nil
  def field(fields, name) when is_list(fields) do
    case List.keyfind(fields, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  @doc "Decodes a JSON response body into an object."
  @spec decode(response()) :: {:ok, [{binary(), term()}]} | {:error, term()}
  def decode(%{body: body}) do
    case JSON.decode_object(body) do
      {:ok, fields} -> {:ok, fields}
      {:error, reason} -> {:error, {:acme_body, reason}}
    end
  end

  @doc """
  Returns the ACME problem document in a response, if it carries one.

  RFC 8555 errors are `application/problem+json` with a `type` URN, and the
  `badNonce` URN specifically means "retry with a fresh nonce", so the caller
  has to be able to see it.
  """
  @spec problem(response()) :: %{type: binary(), detail: binary() | nil} | nil
  def problem(response) do
    with {:ok, fields} <- decode(response),
         type when is_binary(type) <- field(fields, "type") do
      %{type: type, detail: field(fields, "detail")}
    else
      _not_a_problem_document -> nil
    end
  end

  defp send_request(url, options, build) do
    with {:ok, uri} <- parse(url) do
      request = build.(uri, options)

      case HTTPClient.request(uri, request, client_options(options)) do
        {:ok, {status, headers, body}} ->
          {:ok, %{status: status, headers: headers, body: body}}

        {:error, reason} ->
          {:error, {:acme_transport, reason}}
      end
    end
  end

  defp parse(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host} = uri}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _invalid ->
        {:error, {:acme_url, url}}
    end
  end

  defp get_request(uri, _options) do
    [
      "GET ",
      target(uri),
      " HTTP/1.1\r\nHost: ",
      host(uri),
      "\r\nUser-Agent: ",
      @user_agent,
      "\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ]
  end

  defp post_request(uri, _options, body) do
    [
      "POST ",
      target(uri),
      " HTTP/1.1\r\nHost: ",
      host(uri),
      "\r\nUser-Agent: ",
      @user_agent,
      "\r\nContent-Type: ",
      @content_type,
      "\r\nContent-Length: ",
      Integer.to_string(byte_size(body)),
      "\r\nConnection: close\r\n\r\n",
      body
    ]
  end

  defp client_options(options) do
    [
      timeout_ms: Keyword.get(options, :timeout_ms, @timeout_ms),
      max_response_bytes: Keyword.get(options, :max_response_bytes, @max_response_bytes)
    ] ++ Keyword.take(options, [:tls_options])
  end

  defp target(uri) do
    path = if uri.path in [nil, ""], do: "/", else: uri.path
    if is_binary(uri.query), do: path <> "?" <> uri.query, else: path
  end

  defp host(%URI{host: host, scheme: scheme, port: port}) do
    if is_nil(port) or port == URI.default_port(scheme) do
      host
    else
      "#{host}:#{port}"
    end
  end
end
