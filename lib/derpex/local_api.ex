defmodule Derpex.LocalAPI do
  @moduledoc """
  Minimal bounded client for tailscaled's node-key WhoIs LocalAPI.

  This intentionally implements only the request needed by DERP client
  verification and always connects directly to a Unix-domain socket.
  """

  @behaviour Derpex.ClientVerifier

  alias Derpex.Admission.Request
  alias Derpex.JSON

  @local_api_host "local-tailscaled.sock"
  @capability_version 145
  @default_timeout_ms 5_000
  @default_max_response_bytes 1_048_576
  @max_response_head_bytes 16_384
  @max_chunk_line_bytes 1_024

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
    timeout_ms = positive_option!(options, :timeout_ms, @default_timeout_ms)

    max_response_bytes =
      positive_option!(options, :max_response_bytes, @default_max_response_bytes)

    with true <- is_binary(socket_path) and socket_path != "",
         deadline = monotonic_milliseconds() + timeout_ms,
         {:ok, socket} <- connect(socket_path, deadline) do
      try do
        with :ok <- :gen_tcp.send(socket, request(node_key)),
             {:ok, status, body} <- receive_response(socket, deadline, max_response_bytes) do
          interpret_response(status, body)
        else
          {:error, reason} -> {:error, normalize_transport_error(reason)}
        end
      after
        :gen_tcp.close(socket)
      end
    else
      false -> {:error, :invalid_socket_path}
      {:error, reason} -> {:error, {:localapi_unavailable, reason}}
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

  defp connect(socket_path, deadline) do
    with {:ok, timeout} <- remaining_timeout(deadline) do
      :gen_tcp.connect(
        {:local, String.to_charlist(socket_path)},
        0,
        [:binary, packet: :raw, active: false],
        timeout
      )
    end
  end

  defp receive_response(socket, deadline, max_response_bytes) do
    with {:ok, head, read_ahead} <- receive_head(socket, "", deadline),
         {:ok, status, headers} <- parse_head(head),
         {:ok, body} <- receive_body(socket, read_ahead, headers, deadline, max_response_bytes) do
      {:ok, status, body}
    end
  end

  defp receive_head(socket, buffer, deadline) do
    case :binary.match(buffer, "\r\n\r\n") do
      {length, 4} when length <= @max_response_head_bytes ->
        <<head::binary-size(^length), "\r\n\r\n", read_ahead::binary>> = buffer
        {:ok, head, read_ahead}

      {_length, 4} ->
        {:error, :response_head_too_large}

      :nomatch when byte_size(buffer) > @max_response_head_bytes ->
        {:error, :response_head_too_large}

      :nomatch ->
        with {:ok, data} <- receive(socket, deadline) do
          receive_head(socket, buffer <> data, deadline)
        end
    end
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

  defp header(headers, name) do
    case List.keyfind(headers, name, 0) do
      {^name, value} -> value
      nil -> nil
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
    with {:ok, data} <- receive(socket, deadline) do
      receive_exact(socket, buffer <> data, length, deadline)
    end
  end

  defp receive_to_close(_socket, buffer, _deadline, max_response_bytes)
       when byte_size(buffer) > max_response_bytes,
       do: {:error, :response_body_too_large}

  defp receive_to_close(socket, buffer, deadline, max_response_bytes) do
    case receive(socket, deadline) do
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

  defp receive_line(socket, buffer, deadline) do
    case :binary.match(buffer, "\r\n") do
      {length, 2} when length <= @max_chunk_line_bytes ->
        <<line::binary-size(^length), "\r\n", rest::binary>> = buffer
        {:ok, line, rest}

      {_length, 2} ->
        {:error, :chunk_line_too_large}

      :nomatch when byte_size(buffer) > @max_chunk_line_bytes ->
        {:error, :chunk_line_too_large}

      :nomatch ->
        with {:ok, data} <- receive(socket, deadline) do
          receive_line(socket, buffer <> data, deadline)
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
    with {:ok, data} <- receive(socket, deadline) do
      receive_at_least(socket, buffer <> data, bytes, deadline)
    end
  end

  defp receive_trailers(_socket, "\r\n" <> _rest, _deadline, chunks),
    do: {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

  defp receive_trailers(socket, buffer, deadline, chunks) do
    case :binary.match(buffer, "\r\n\r\n") do
      {length, 4} when length <= @max_response_head_bytes ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {_length, 4} ->
        {:error, :response_trailers_too_large}

      :nomatch when byte_size(buffer) > @max_response_head_bytes ->
        {:error, :response_trailers_too_large}

      :nomatch ->
        with {:ok, data} <- receive(socket, deadline) do
          receive_trailers(socket, buffer <> data, deadline, chunks)
        end
    end
  end

  defp receive(socket, deadline) do
    with {:ok, timeout} <- remaining_timeout(deadline) do
      :gen_tcp.recv(socket, 0, timeout)
    end
  end

  defp remaining_timeout(deadline) do
    case deadline - monotonic_milliseconds() do
      remaining when remaining > 0 -> {:ok, remaining}
      _expired -> {:error, :timeout}
    end
  end

  defp monotonic_milliseconds, do: System.monotonic_time(:millisecond)

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

  defp normalize_transport_error(reason), do: {:invalid_localapi_response, reason}

  defp positive_option!(options, name, default) do
    case Keyword.get(options, name, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{name} must be a positive integer"
    end
  end
end
