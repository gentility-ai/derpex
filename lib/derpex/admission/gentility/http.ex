defmodule Derpex.Admission.Gentility.HTTP do
  @moduledoc """
  The Gentility control plane over HTTPS: the `ControlPlane` a relay runs with
  `DERPEX_GENTILITY_ADAPTER=http`.

  Three routes on the Gentility app, each called with the relay's instance id
  in `x-derp-instance` and its secret as a bearer:

    * `POST /overlay/derp/authorize` with `{"node_key": <64 lowercase hex>,
      "renewal": <bool>, "region_id": <int>}`. A 200 body is a signed record,
      a `DXAL` lease or a `DXRV` revocation, returned as it came. Every other
      answer — a 404 for a key Gentility does not know, any other status, a
      timeout, a refused connection — is `{:error, reason}`: the plane could
      not answer, which ADR 0002 never reads as a denial.
    * `GET /overlay/derp/revocations?cursor=&wait_ms=` waits up to `wait_ms`
      for the next revocation after the cursor. A 200 carries one `DXRV` and
      a 204 none; both carry the next cursor in `x-derp-cursor`. A 409 means
      Gentility no longer holds the cursor, so the relay reconciles.
    * `GET /overlay/derp/reconcile?cursor=` answers one page: zero or more
      `DXRV`s, each behind its byte length as an unsigned 16-bit big-endian
      integer, and the cursor after the last in `x-derp-cursor`. A page with no
      cursor ends the pass.

  The relay sends no source address. A renewal has none, and a fresh
  connection's is used only by confinement, inside the relay. Nothing here
  logs a source address, a node key or the bearer.

  Usage is not exported: Gentility has no usage route yet. Every batch is
  acknowledged as `{:ok, :discarded}`, which `UsageWorker` counts in
  `derpex_gentility_usage_discarded_total`, and dropped from the spool.
  """

  @behaviour Derpex.Admission.Gentility.ControlPlane

  alias Derpex.Admission.Request
  alias Derpex.HTTPClient
  alias Derpex.JSON
  alias Derpex.Secret

  @authorize_path "/overlay/derp/authorize"
  @revocations_path "/overlay/derp/revocations"
  @reconcile_path "/overlay/derp/reconcile"
  @cursor_header "x-derp-cursor"

  @default_timeout_ms 2_000
  @default_reconcile_timeout_ms 10_000
  # Gentility holds a stream poll for at most this long, under every proxy
  # timeout between the relay and the app.
  @max_wait_ms 25_000
  # The poll's own HTTP deadline is this much longer than the wait it asks for,
  # so a 204 that arrives on time is never cut off by the relay's own timer.
  @wait_margin_ms 5_000
  @min_token_bytes 32
  @max_record_bytes 4_096
  @max_page_bytes 8 * 1_024 * 1_024

  @type options :: keyword()

  @doc """
  Validates the adapter's settings and returns its options, with the bearer
  wrapped so it renders without its bytes.

  `url` is the app's base URL, `token` the bearer (at least 32 bytes),
  `instance_id` the relay's name for itself, and `region_id` its region.
  """
  @spec config(keyword()) :: {:ok, options()} | {:error, atom()}
  def config(settings) when is_list(settings) do
    with {:ok, url} <- base_url(Keyword.get(settings, :url)),
         {:ok, token} <- token(Keyword.get(settings, :token)),
         {:ok, instance_id} <- instance_id(Keyword.get(settings, :instance_id)),
         {:ok, region_id} <- region_id(Keyword.get(settings, :region_id)) do
      {:ok,
       [
         url: url,
         token: Secret.wrap(token),
         instance_id: instance_id,
         region_id: region_id,
         timeout_ms: Keyword.get(settings, :timeout_ms, @default_timeout_ms),
         reconcile_timeout_ms:
           Keyword.get(settings, :reconcile_timeout_ms, @default_reconcile_timeout_ms),
         tls_options: Keyword.get(settings, :tls_options, [])
       ]}
    end
  end

  @impl true
  def authorize(%Request{node_key: <<_::256>> = node_key, metadata: metadata}, options) do
    body =
      JSON.encode_object([
        {"node_key", Base.encode16(node_key, case: :lower)},
        {"renewal", renewal?(metadata)},
        {"region_id", Keyword.fetch!(options, :region_id)}
      ])

    case call(options, "POST", @authorize_path, body, timeout_ms(options), @max_record_bytes) do
      {:ok, {200, _headers, record}} when record != "" -> {:ok, record}
      {:ok, {status, _headers, _body}} -> {:error, {:http, status}}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  def next_revocation(cursor, timeout_ms, options)
      when is_binary(cursor) and is_integer(timeout_ms) and timeout_ms > 0 do
    wait_ms = timeout_ms |> Kernel.-(@wait_margin_ms) |> min(@max_wait_ms) |> max(0)
    path = @revocations_path <> "?" <> URI.encode_query(cursor: cursor, wait_ms: wait_ms)

    case call(options, "GET", path, nil, wait_ms + @wait_margin_ms, @max_record_bytes) do
      {:ok, {200, headers, record}} when record != "" -> with_cursor(headers, &{:ok, record, &1})
      {:ok, {204, headers, _body}} -> with_cursor(headers, &{:timeout, &1})
      {:ok, {409, _headers, _body}} -> {:error, :cursor_not_held}
      {:ok, {status, _headers, _body}} -> {:error, {:http, status}}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  def reconcile(cursor, options) when is_nil(cursor) or is_binary(cursor) do
    path = @reconcile_path <> "?" <> URI.encode_query(cursor: cursor || "")
    timeout = Keyword.fetch!(options, :reconcile_timeout_ms)

    case call(options, "GET", path, nil, timeout, @max_page_bytes) do
      {:ok, {200, headers, body}} -> page(body, HTTPClient.header(headers, @cursor_header))
      {:ok, {409, _headers, _body}} -> {:error, :cursor_not_held}
      {:ok, {status, _headers, _body}} -> {:error, {:http, status}}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  def export_usage(<<_::256>>, wire, _options) when is_binary(wire), do: {:ok, :discarded}

  defp renewal?(%{renewal: true}), do: true
  defp renewal?(_metadata), do: false

  defp timeout_ms(options), do: Keyword.fetch!(options, :timeout_ms)

  defp with_cursor(headers, reply) do
    case HTTPClient.header(headers, @cursor_header) do
      cursor when is_binary(cursor) and cursor != "" -> reply.(cursor)
      _missing -> {:error, :missing_cursor}
    end
  end

  # A page with records always carries the position after them; only the empty
  # page that ends a pass carries none.
  defp page("", nil), do: {:ok, [], nil}
  defp page(_body, nil), do: {:error, :invalid_reconcile_page}
  defp page(_body, ""), do: {:error, :invalid_reconcile_page}

  defp page(body, cursor) do
    case records(body, []) do
      {:ok, records} -> {:ok, records, cursor}
      :error -> {:error, :invalid_reconcile_page}
    end
  end

  defp records(<<>>, records), do: {:ok, Enum.reverse(records)}

  defp records(<<length::16, record::binary-size(length), rest::binary>>, records)
       when length > 0,
       do: records(rest, [record | records])

  defp records(_malformed, _records), do: :error

  defp call(options, method, path, body, timeout_ms, max_response_bytes) do
    url = Keyword.fetch!(options, :url)

    http_options = [
      timeout_ms: timeout_ms,
      max_response_bytes: max_response_bytes,
      tls_options: Keyword.get(options, :tls_options, [])
    ]

    HTTPClient.request(url, request(method, url, path, body, options), http_options)
  end

  defp request(method, url, path, body, options) do
    [
      method,
      " ",
      base_path(url),
      path,
      " HTTP/1.1\r\nHost: ",
      host_header(url),
      "\r\nx-derp-instance: ",
      Keyword.fetch!(options, :instance_id),
      "\r\nauthorization: Bearer ",
      options |> Keyword.fetch!(:token) |> Secret.reveal(),
      "\r\n",
      body_headers(body),
      "Connection: close\r\n\r\n",
      body || []
    ]
  end

  defp body_headers(nil), do: []

  defp body_headers(body) do
    [
      "content-type: application/json\r\ncontent-length: ",
      Integer.to_string(byte_size(body)),
      "\r\n"
    ]
  end

  defp base_path(%URI{path: path}) when path in [nil, "", "/"], do: ""
  defp base_path(%URI{path: path}), do: String.trim_trailing(path, "/")

  defp host_header(%URI{host: host, scheme: scheme, port: port}) do
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host

    if port in [nil, URI.default_port(scheme)],
      do: host,
      else: host <> ":" <> Integer.to_string(port)
  end

  defp base_url(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host, query: nil, fragment: nil, userinfo: nil} = uri}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _invalid ->
        {:error, :invalid_url}
    end
  end

  defp base_url(_url), do: {:error, :invalid_url}

  # The bearer and the instance id are written into a request head, so each is
  # held to visible ASCII: no space, no control byte, nothing that ends a line.
  defp token(token) when is_binary(token) and byte_size(token) >= @min_token_bytes do
    if header_value?(token), do: {:ok, token}, else: {:error, :invalid_token}
  end

  defp token(_token), do: {:error, :invalid_token}

  defp instance_id(id) when is_binary(id) and byte_size(id) in 1..512 do
    if header_value?(id), do: {:ok, id}, else: {:error, :invalid_instance_id}
  end

  defp instance_id(_id), do: {:error, :invalid_instance_id}

  defp region_id(region_id) when is_integer(region_id) and region_id in 0..0xFFFF_FFFF,
    do: {:ok, region_id}

  defp region_id(_region_id), do: {:error, :invalid_region_id}

  defp header_value?(value), do: value |> :binary.bin_to_list() |> Enum.all?(&(&1 in 0x21..0x7E))
end
