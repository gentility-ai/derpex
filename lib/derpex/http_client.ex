defmodule Derpex.HTTPClient do
  @moduledoc false

  @default_timeout_ms 5_000
  @default_max_response_bytes 1_048_576
  @max_response_head_bytes 16_384
  @max_chunk_line_bytes 1_024

  @type target :: {:unix, Path.t()} | URI.t()
  @type response :: {100..999, [{binary(), binary()}], binary()}
  @type options :: [
          timeout_ms: pos_integer(),
          max_response_bytes: pos_integer(),
          tls_options: keyword()
        ]

  @spec request(target(), iodata(), options()) :: {:ok, response()} | {:error, term()}
  def request(target, request, options \\ []) when is_list(options) do
    timeout_ms = positive_option!(options, :timeout_ms, @default_timeout_ms)

    max_response_bytes =
      positive_option!(options, :max_response_bytes, @default_max_response_bytes)

    deadline = monotonic_milliseconds() + timeout_ms

    case connect(target, deadline, options) do
      {:ok, socket} ->
        try do
          case send_data(socket, request) do
            :ok -> receive_response(socket, deadline, max_response_bytes)
            {:error, reason} -> {:error, {:send, reason}}
          end
        after
          close(socket)
        end

      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  @spec header([{binary(), binary()}], binary()) :: binary() | nil
  def header(headers, name) when is_list(headers) and is_binary(name) do
    name = String.downcase(name, :ascii)

    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp connect({:unix, socket_path}, deadline, _options)
       when is_binary(socket_path) and socket_path != "" do
    with {:ok, timeout} <- remaining_timeout(deadline),
         {:ok, socket} <-
           :gen_tcp.connect(
             {:local, String.to_charlist(socket_path)},
             0,
             [:binary, packet: :raw, active: false],
             timeout
           ) do
      {:ok, {:tcp, socket}}
    end
  end

  defp connect(%URI{scheme: "http", host: host} = uri, deadline, _options)
       when is_binary(host) do
    with {:ok, timeout} <- remaining_timeout(deadline),
         {:ok, socket} <-
           :gen_tcp.connect(
             String.to_charlist(host),
             uri.port || 80,
             [:binary, packet: :raw, active: false, nodelay: true],
             timeout
           ) do
      {:ok, {:tcp, socket}}
    end
  end

  defp connect(%URI{scheme: "https", host: host} = uri, deadline, options)
       when is_binary(host) do
    with {:ok, timeout} <- remaining_timeout(deadline),
         {:ok, socket} <-
           :ssl.connect(
             String.to_charlist(host),
             uri.port || 443,
             tls_options(host, options),
             timeout
           ) do
      {:ok, {:ssl, socket}}
    end
  end

  defp connect(_target, _deadline, _options), do: {:error, :invalid_target}

  defp tls_options(host, options) do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: String.to_charlist(host),
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      mode: :binary,
      packet: :raw,
      active: false
    ]
    |> Keyword.merge(Keyword.get(options, :tls_options, []))
    |> Keyword.put(:mode, :binary)
    |> Keyword.put(:packet, :raw)
    |> Keyword.put(:active, false)
  end

  defp send_data({:tcp, socket}, data), do: :gen_tcp.send(socket, data)
  defp send_data({:ssl, socket}, data), do: :ssl.send(socket, data)

  defp close({:tcp, socket}), do: :gen_tcp.close(socket)
  defp close({:ssl, socket}), do: :ssl.close(socket)

  defp receive_response(socket, deadline, max_response_bytes) do
    case receive_head(socket, "", 0, deadline) do
      {:ok, head, read_ahead} ->
        receive_parsed_response(socket, head, read_ahead, deadline, max_response_bytes)

      {:error, reason} ->
        {:error, {:response_head, reason}}
    end
  end

  defp receive_parsed_response(socket, head, read_ahead, deadline, max_response_bytes) do
    case parse_head(head) do
      {:ok, status, headers} ->
        case receive_body(socket, read_ahead, headers, deadline, max_response_bytes) do
          {:ok, body} -> {:ok, {status, headers, body}}
          {:error, reason} -> {:error, {:response_body, reason}}
        end

      {:error, reason} ->
        {:error, {:response_head, reason}}
    end
  end

  defp receive_head(socket, buffer, scanned, deadline) do
    case match_from(buffer, scanned, "\r\n\r\n") do
      {length, 4} when length <= @max_response_head_bytes ->
        <<head::binary-size(^length), "\r\n\r\n", read_ahead::binary>> = buffer
        {:ok, head, read_ahead}

      {_length, 4} ->
        {:error, :response_head_too_large}

      :nomatch when byte_size(buffer) > @max_response_head_bytes ->
        {:error, :response_head_too_large}

      :nomatch ->
        with {:ok, data} <- receive_data(socket, deadline) do
          receive_head(socket, buffer <> data, byte_size(buffer), deadline)
        end
    end
  end

  # Rescans only the bytes that could hold a terminator straddling the previous
  # read boundary, keeping incremental reads linear rather than quadratic.
  defp match_from(buffer, scanned, pattern) do
    start = max(0, scanned - (byte_size(pattern) - 1))
    :binary.match(buffer, pattern, scope: {start, byte_size(buffer) - start})
  end

  defp parse_head(head) do
    case :binary.split(head, "\r\n", [:global]) do
      [status_line | header_lines] ->
        with {:ok, status} <- parse_status(status_line),
             {:ok, headers} <- parse_headers(header_lines, []) do
          {:ok, status, headers}
        end

      [] ->
        {:error, :invalid_response_head}
    end
  end

  defp parse_status(status_line) do
    case :binary.split(status_line, " ", [:global]) do
      [version, status_text | _reason] when version in ["HTTP/1.0", "HTTP/1.1"] ->
        case Integer.parse(status_text) do
          {status, ""} when status in 100..999 -> {:ok, status}
          _invalid -> {:error, :invalid_response_status}
        end

      _invalid ->
        {:error, :invalid_response_status}
    end
  end

  defp parse_headers([], headers), do: {:ok, Enum.reverse(headers)}

  defp parse_headers([line | rest], headers) do
    case :binary.split(line, ":") do
      [name, value] when name != "" ->
        header = {String.downcase(name, :ascii), String.trim(value)}
        parse_headers(rest, [header | headers])

      _invalid ->
        {:error, :invalid_response_header}
    end
  end

  defp receive_body(socket, read_ahead, headers, deadline, max_response_bytes) do
    cond do
      chunked?(headers) ->
        receive_chunked(socket, read_ahead, deadline, max_response_bytes, [], 0)

      content_length = header(headers, "content-length") ->
        with {:ok, length} <- parse_content_length(content_length),
             true <- length <= max_response_bytes,
             {:ok, body} <- receive_exact(socket, read_ahead, length, deadline) do
          {:ok, body}
        else
          false -> {:error, :response_body_too_large}
          {:error, _reason} = error -> error
        end

      true ->
        receive_to_close(socket, read_ahead, deadline, max_response_bytes)
    end
  end

  defp chunked?(headers) do
    headers
    |> header("transfer-encoding")
    |> case do
      nil ->
        false

      value ->
        value
        |> String.downcase(:ascii)
        |> String.split(",")
        |> Enum.any?(&(String.trim(&1) == "chunked"))
    end
  end

  defp parse_content_length(value) do
    case Integer.parse(value) do
      {length, ""} when length >= 0 -> {:ok, length}
      _invalid -> {:error, :invalid_content_length}
    end
  end

  defp receive_exact(_socket, buffer, length, _deadline) when byte_size(buffer) >= length do
    {:ok, binary_part(buffer, 0, length)}
  end

  defp receive_exact(socket, buffer, length, deadline) do
    with {:ok, data} <- receive_data(socket, deadline) do
      receive_exact(socket, buffer <> data, length, deadline)
    end
  end

  defp receive_to_close(_socket, buffer, _deadline, max_response_bytes)
       when byte_size(buffer) > max_response_bytes,
       do: {:error, :response_body_too_large}

  defp receive_to_close(socket, buffer, deadline, max_response_bytes) do
    case receive_data(socket, deadline) do
      {:ok, data} -> receive_to_close(socket, buffer <> data, deadline, max_response_bytes)
      {:error, :closed} -> {:ok, buffer}
      {:error, reason} -> {:error, reason}
    end
  end

  defp receive_chunked(socket, buffer, deadline, limit, chunks, total) do
    with {:ok, line, rest} <- receive_line(socket, buffer, deadline),
         {:ok, size} <- parse_chunk_size(line),
         true <- total + size <= limit do
      receive_chunk(socket, rest, deadline, limit, chunks, total, size)
    else
      false -> {:error, :response_body_too_large}
      {:error, _reason} = error -> error
    end
  end

  defp receive_chunk(socket, rest, deadline, _limit, chunks, _total, 0) do
    receive_trailers(socket, rest, deadline, chunks)
  end

  defp receive_chunk(socket, rest, deadline, limit, chunks, total, size) do
    with {:ok, chunk_and_suffix} <- receive_at_least(socket, rest, size + 2, deadline),
         <<chunk::binary-size(^size), "\r\n", next::binary>> <- chunk_and_suffix do
      receive_chunked(socket, next, deadline, limit, [chunk | chunks], total + size)
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_chunk_terminator}
    end
  end

  defp receive_line(socket, buffer, deadline), do: receive_line(socket, buffer, 0, deadline)

  defp receive_line(socket, buffer, scanned, deadline) do
    case match_from(buffer, scanned, "\r\n") do
      {length, 2} when length <= @max_chunk_line_bytes ->
        <<line::binary-size(^length), "\r\n", rest::binary>> = buffer
        {:ok, line, rest}

      {_length, 2} ->
        {:error, :chunk_line_too_large}

      :nomatch when byte_size(buffer) > @max_chunk_line_bytes ->
        {:error, :chunk_line_too_large}

      :nomatch ->
        with {:ok, data} <- receive_data(socket, deadline) do
          receive_line(socket, buffer <> data, byte_size(buffer), deadline)
        end
    end
  end

  defp parse_chunk_size(line) do
    size_text = line |> :binary.split(";") |> hd() |> String.trim()

    case Integer.parse(size_text, 16) do
      {size, ""} when size >= 0 -> {:ok, size}
      _invalid -> {:error, :invalid_chunk_size}
    end
  end

  defp receive_at_least(_socket, buffer, bytes, _deadline) when byte_size(buffer) >= bytes,
    do: {:ok, buffer}

  defp receive_at_least(socket, buffer, bytes, deadline) do
    with {:ok, data} <- receive_data(socket, deadline) do
      receive_at_least(socket, buffer <> data, bytes, deadline)
    end
  end

  defp receive_trailers(socket, buffer, deadline, chunks),
    do: receive_trailers(socket, buffer, 0, deadline, chunks)

  defp receive_trailers(_socket, "\r\n" <> _rest, _scanned, _deadline, chunks),
    do: {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

  defp receive_trailers(socket, buffer, scanned, deadline, chunks) do
    case match_from(buffer, scanned, "\r\n\r\n") do
      {length, 4} when length <= @max_response_head_bytes ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {_length, 4} ->
        {:error, :response_trailers_too_large}

      :nomatch when byte_size(buffer) > @max_response_head_bytes ->
        {:error, :response_trailers_too_large}

      :nomatch ->
        with {:ok, data} <- receive_data(socket, deadline) do
          receive_trailers(socket, buffer <> data, byte_size(buffer), deadline, chunks)
        end
    end
  end

  defp receive_data({:tcp, socket}, deadline) do
    with {:ok, timeout} <- remaining_timeout(deadline) do
      :gen_tcp.recv(socket, 0, timeout)
    end
  end

  defp receive_data({:ssl, socket}, deadline) do
    with {:ok, timeout} <- remaining_timeout(deadline) do
      :ssl.recv(socket, 0, timeout)
    end
  end

  defp remaining_timeout(deadline) do
    case deadline - monotonic_milliseconds() do
      remaining when remaining > 0 -> {:ok, remaining}
      _expired -> {:error, :timeout}
    end
  end

  defp monotonic_milliseconds, do: System.monotonic_time(:millisecond)

  defp positive_option!(options, name, default) do
    case Keyword.get(options, name, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{name} must be a positive integer"
    end
  end
end
