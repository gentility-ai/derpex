defmodule Derpex.Mesh.Client do
  @moduledoc """
  Long-lived outbound DERP mesh connection.

  The client watches one peer server, registers its advertised clients as
  regional routes, and forwards packets through a fixed-capacity ring. A
  broken connection withdraws every learned route before reconnecting.
  """

  use GenServer

  alias Derpex.ClientInfo
  alias Derpex.Clock
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Frame.Decoder
  alias Derpex.Handshake
  alias Derpex.Mesh.ClientAddressTable
  alias Derpex.Outbox.Ring
  alias Derpex.Router

  @wake_message :derpex_mesh_outbox_ready
  @reconnect_message :derpex_mesh_reconnect
  @default_reconnect_interval 5_000
  @default_connect_timeout 10_000
  @default_queue_capacity 32
  @max_http_head_bytes 1 * 1_024 * 1_024
  @max_server_frame_bytes Frame.max_info_length() + Frame.nonce_length()

  @type status :: %{
          connected?: boolean(),
          disabled?: boolean(),
          remote_server_key: nil | binary(),
          remote_peer_count: non_neg_integer(),
          last_error: nil | term()
        }

  @doc false
  def start_link(options) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns the current connection and learned-route state."
  @spec status(GenServer.server()) :: status()
  def status(client), do: GenServer.call(client, :status)

  @doc "Returns the cached local socket address without calling the client process."
  @spec local_address(pid()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, :not_connected}
  def local_address(client) when is_pid(client), do: ClientAddressTable.fetch(client)

  @doc "Closes the active socket so tests and operators can force reconnection."
  @spec break_connection(GenServer.server()) :: :ok
  def break_connection(client), do: GenServer.call(client, :break_connection)

  @impl true
  def init(options) do
    with {:ok, endpoint} <- parse_endpoint(Keyword.fetch!(options, :url)),
         {:ok, proxy} <- parse_proxy(Keyword.get(options, :proxy_url)),
         <<private_key::binary-size(32)>> <- Keyword.fetch!(options, :private_key),
         <<mesh_key::binary-size(32)>> <- Keyword.fetch!(options, :mesh_key),
         {:ok, local_public_key} <- Crypto.public_key(private_key) do
      endpoint = %{endpoint | dial_host: Keyword.get(options, :dial_host, endpoint.host)}

      state = %{
        endpoint: endpoint,
        proxy: proxy,
        private_key: private_key,
        local_public_key: local_public_key,
        mesh_key: mesh_key,
        router: Keyword.get(options, :router, Router),
        event_handler: Keyword.get(options, :event_handler, fn _event -> :ok end),
        reconnect_interval:
          non_negative_option!(options, :reconnect_interval, @default_reconnect_interval),
        connect_timeout: positive_option!(options, :connect_timeout, @default_connect_timeout),
        queue_capacity: positive_option!(options, :queue_capacity, @default_queue_capacity),
        tls_options: Keyword.get(options, :tls_options, []),
        socket: nil,
        decoder: Decoder.new(max_frame_length: @max_server_frame_bytes),
        ring: nil,
        remote_server_key: nil,
        remote_peers: MapSet.new(),
        reconnect_timer: nil,
        disabled?: false,
        last_error: nil
      }

      {:ok, %{state | ring: new_ring(state)}, {:continue, :connect}}
    else
      _invalid -> {:stop, :invalid_mesh_client_options}
    end
  end

  @impl true
  def handle_continue(:connect, state), do: connect_or_retry(state)

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      connected?: state.socket != nil,
      disabled?: state.disabled?,
      remote_server_key: state.remote_server_key,
      remote_peer_count: MapSet.size(state.remote_peers),
      last_error: state.last_error
    }

    {:reply, status, state}
  end

  def handle_call(:break_connection, _from, state) do
    {:reply, :ok, disconnect_and_retry(state, :connection_broken)}
  end

  @impl true
  def handle_info({@reconnect_message, token}, %{reconnect_timer: {token, _timer}} = state) do
    connect_or_retry(%{state | reconnect_timer: nil})
  end

  def handle_info({@reconnect_message, _stale_token}, state), do: {:noreply, state}

  def handle_info(@wake_message, %{socket: nil} = state), do: {:noreply, state}

  def handle_info(@wake_message, state) do
    case drain_forwarded_packets(state) do
      :ok -> {:noreply, state}
      {:error, reason} -> {:noreply, disconnect_and_retry(state, reason)}
    end
  end

  def handle_info({:tcp, socket, data}, %{socket: {:tcp, socket}} = state),
    do: receive_socket_data(state, data)

  def handle_info({:ssl, socket, data}, %{socket: {:ssl, socket}} = state),
    do: receive_socket_data(state, data)

  def handle_info({:tcp_closed, socket}, %{socket: {:tcp, socket}} = state),
    do: {:noreply, disconnect_and_retry(state, :closed)}

  def handle_info({:ssl_closed, socket}, %{socket: {:ssl, socket}} = state),
    do: {:noreply, disconnect_and_retry(state, :closed)}

  def handle_info({:tcp_error, socket, reason}, %{socket: {:tcp, socket}} = state),
    do: {:noreply, disconnect_and_retry(state, reason)}

  def handle_info({:ssl_error, socket, reason}, %{socket: {:ssl, socket}} = state),
    do: {:noreply, disconnect_and_retry(state, reason)}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    ClientAddressTable.delete(self())
    _state = withdraw_remote_peers(state)
    close_socket(state.socket)
    cancel_reconnect(state.reconnect_timer)
    close_ring(state.ring)
    :ok
  end

  defp connect_or_retry(%{disabled?: true} = state), do: {:noreply, state}

  defp connect_or_retry(state) do
    case establish_connection(state) do
      {:ok, state, read_ahead} ->
        state = cancel_reconnect_timer(state)

        with {:ok, state} <- process_server_data(state, read_ahead),
             :ok <- active_once(state.socket),
             :ok <- cache_local_address(state.socket) do
          dispatch_event(state, {:connected, state.remote_server_key})
          {:noreply, %{state | last_error: nil}}
        else
          {:error, reason} -> {:noreply, disconnect_and_retry(state, reason)}
        end

      {:self_connect, state} ->
        dispatch_event(state, {:self_connect, state.remote_server_key})
        {:noreply, %{state | disabled?: true, socket: nil}}

      {:error, reason, state} ->
        {:noreply, disconnect_and_retry(state, reason)}
    end
  end

  defp establish_connection(state) do
    case open_socket(state) do
      {:ok, socket} ->
        case perform_handshake(%{state | socket: socket}) do
          {:ok, connected_state, read_ahead} ->
            {:ok, connected_state, read_ahead}

          {:self_connect, connected_state} ->
            close_socket(socket)
            {:self_connect, connected_state}

          {:error, reason, failed_state} ->
            close_socket(socket)
            {:error, reason, %{failed_state | socket: nil}}
        end

      {:error, reason} ->
        {:error, {:connect, reason}, state}
    end
  end

  defp perform_handshake(state) do
    with :ok <- socket_send(state.socket, upgrade_request(state.endpoint)),
         {:ok, read_ahead} <- receive_http_upgrade(state.socket, state.connect_timeout),
         {:ok, type, server_key_body, read_ahead} <-
           receive_frame(state.socket, read_ahead, state.connect_timeout),
         true <- type == Frame.type(:server_key),
         {:ok, remote_server_key} <- Handshake.decode_server_key(server_key_body) do
      state = %{state | remote_server_key: remote_server_key}

      if remote_server_key == state.local_public_key do
        {:self_connect, state}
      else
        finish_handshake(state, read_ahead)
      end
    else
      false -> {:error, :expected_server_key, state}
      {:error, reason} -> {:error, {:handshake, reason}, state}
    end
  end

  defp finish_handshake(state, read_ahead) do
    info = %ClientInfo{
      version: Handshake.protocol_version(),
      mesh_key: state.mesh_key,
      can_ack_pings: true,
      app_name: "derpex"
    }

    with {:ok, client_info} <-
           Handshake.client_info_frame(
             state.private_key,
             state.remote_server_key,
             info
           ),
         {:ok, watch} <- Body.encode_client(:watch_connections),
         :ok <- socket_send(state.socket, [client_info, watch]),
         {:ok, type, server_info_body, read_ahead} <-
           receive_frame(state.socket, read_ahead, state.connect_timeout),
         true <- type == Frame.type(:server_info),
         {:ok, _server_info} <-
           Handshake.decode_server_info(
             server_info_body,
             state.private_key,
             state.remote_server_key
           ) do
      {:ok, %{state | decoder: Decoder.new(max_frame_length: @max_server_frame_bytes)},
       read_ahead}
    else
      false -> {:error, :expected_server_info, state}
      {:error, reason} -> {:error, {:handshake, reason}, state}
    end
  end

  defp receive_socket_data(state, data) do
    case process_server_data(state, data) do
      {:ok, state} ->
        case active_once(state.socket) do
          :ok -> {:noreply, state}
          {:error, reason} -> {:noreply, disconnect_and_retry(state, reason)}
        end

      {:error, reason} ->
        {:noreply, disconnect_and_retry(state, reason)}
    end
  end

  defp process_server_data(state, ""), do: {:ok, state}

  defp process_server_data(state, data) do
    case Decoder.push(state.decoder, data) do
      {:ok, frames, decoder} ->
        process_server_frames(frames, %{state | decoder: decoder})

      {:error, reason} ->
        {:error, {:frame, reason}}
    end
  end

  defp process_server_frames(frames, state) do
    Enum.reduce_while(frames, {:ok, state}, fn frame, {:ok, state} ->
      case process_server_frame(state, frame) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp process_server_frame(state, {type, payload}) do
    case Body.decode_server(type, payload) do
      {:ok, {:peer_present, key, _ip, _port, _flags, _app_name}} ->
        :ok = state.router.add_forwarder(key, self(), state.ring)
        dispatch_event(state, {:peer_present, key})
        {:ok, %{state | remote_peers: MapSet.put(state.remote_peers, key)}}

      {:ok, {:peer_gone, key, reason}} ->
        :ok = state.router.remove_forwarder(key, self())
        dispatch_event(state, {:peer_gone, key, reason})
        {:ok, %{state | remote_peers: MapSet.delete(state.remote_peers, key)}}

      {:ok, {:ping, payload}} ->
        with {:ok, pong} <- Body.encode_client({:pong, payload}),
             :ok <- socket_send(state.socket, pong) do
          {:ok, state}
        end

      {:ok, _message} ->
        {:ok, state}

      {:drop, _reason} ->
        {:ok, state}

      :ignore ->
        {:ok, state}
    end
  end

  defp drain_forwarded_packets(state) do
    case Ring.take(state.ring) do
      {:ok, {:forward_packet, source, destination, packet}} ->
        with {:ok, frame} <- Body.encode_client({:forward_packet, source, destination, packet}),
             :ok <- socket_send(state.socket, frame) do
          drain_forwarded_packets(state)
        end

      :empty ->
        :ok

      :busy ->
        send(self(), @wake_message)
        :ok

      :closed ->
        :ok
    end
  end

  defp disconnect_and_retry(state, reason) do
    was_connected? = state.socket != nil
    ClientAddressTable.delete(self())
    close_socket(state.socket)
    state = withdraw_remote_peers(state)
    close_ring(state.ring)

    state = %{
      state
      | socket: nil,
        decoder: Decoder.new(max_frame_length: @max_server_frame_bytes),
        ring: new_ring(state),
        remote_server_key: nil,
        last_error: reason
    }

    if was_connected? do
      dispatch_event(state, {:disconnected, reason})
    else
      dispatch_event(state, {:connect_error, reason})
    end

    schedule_reconnect(state)
  end

  defp withdraw_remote_peers(state) do
    Enum.each(state.remote_peers, fn key ->
      :ok = state.router.remove_forwarder(key, self())
    end)

    %{state | remote_peers: MapSet.new()}
  end

  defp schedule_reconnect(%{disabled?: true} = state), do: state
  defp schedule_reconnect(%{reconnect_timer: {_token, _timer}} = state), do: state

  defp schedule_reconnect(state) do
    token = make_ref()

    timer =
      Clock.send_after(
        self(),
        {@reconnect_message, token},
        state.reconnect_interval
      )

    %{state | reconnect_timer: {token, timer}}
  end

  defp cancel_reconnect_timer(%{reconnect_timer: reconnect_timer} = state) do
    cancel_reconnect(reconnect_timer)
    %{state | reconnect_timer: nil}
  end

  defp cancel_reconnect(nil), do: :ok

  defp cancel_reconnect({_token, timer}) do
    _remaining = Clock.cancel_timer(timer)
    :ok
  end

  defp new_ring(state) do
    Ring.new(state.queue_capacity, notifier: self(), wake_message: @wake_message)
  end

  defp close_ring(nil), do: :ok

  defp close_ring(%Ring{} = ring) do
    _result = Ring.close(ring)
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp open_socket(%{proxy: nil} = state) do
    endpoint = state.endpoint
    host = String.to_charlist(endpoint.dial_host)
    tcp_options = [:binary, packet: :raw, active: false, nodelay: true]

    case endpoint.scheme do
      "http" ->
        case :gen_tcp.connect(host, endpoint.port, tcp_options, state.connect_timeout) do
          {:ok, socket} -> {:ok, {:tcp, socket}}
          {:error, reason} -> {:error, reason}
        end

      "https" ->
        case :ssl.connect(host, endpoint.port, tls_options(state), state.connect_timeout) do
          {:ok, socket} -> {:ok, {:ssl, socket}}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp open_socket(state) do
    proxy = state.proxy
    tcp_options = [:binary, packet: :raw, active: false, nodelay: true]

    case :gen_tcp.connect(
           String.to_charlist(proxy.host),
           proxy.port,
           tcp_options,
           state.connect_timeout
         ) do
      {:ok, socket} -> open_proxy_tunnel(state, socket)
      {:error, reason} -> {:error, {:proxy_connect, reason}}
    end
  end

  defp open_proxy_tunnel(state, socket) do
    target = host_and_port(state.endpoint.host, state.endpoint.port)

    result =
      with :ok <- :gen_tcp.send(socket, proxy_connect_request(target, state.proxy)),
           :ok <- receive_proxy_response(socket, "", state.connect_timeout) do
        case state.endpoint.scheme do
          "http" -> {:ok, {:tcp, socket}}
          "https" -> wrap_proxy_tls(state, socket)
        end
      end

    case result do
      {:ok, _socket} = connected ->
        connected

      {:error, _reason} = error ->
        :gen_tcp.close(socket)
        error
    end
  end

  defp wrap_proxy_tls(state, socket) do
    case :ssl.connect(socket, tls_options(state), state.connect_timeout) do
      {:ok, tls_socket} -> {:ok, {:ssl, tls_socket}}
      {:error, reason} -> {:error, {:proxy_tls, reason}}
    end
  end

  defp receive_proxy_response(_socket, buffer, _timeout)
       when byte_size(buffer) > @max_http_head_bytes,
       do: {:error, :proxy_response_too_large}

  defp receive_proxy_response(socket, buffer, timeout) do
    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} ->
        <<head::binary-size(^head_length), "\r\n\r\n", _read_ahead::binary>> = buffer

        case :binary.split(head, "\r\n") do
          [status_line | _headers] -> validate_proxy_status(status_line)
        end

      :nomatch ->
        case :gen_tcp.recv(socket, 0, timeout) do
          {:ok, data} -> receive_proxy_response(socket, buffer <> data, timeout)
          {:error, reason} -> {:error, {:proxy_response, reason}}
        end
    end
  end

  defp validate_proxy_status(status_line) do
    case :binary.split(status_line, " ", [:global]) do
      [version, "200" | _rest] when version in ["HTTP/1.0", "HTTP/1.1"] -> :ok
      _other -> {:error, {:proxy_status, status_line}}
    end
  end

  defp proxy_connect_request(target, proxy) do
    [
      "CONNECT ",
      target,
      " HTTP/1.1\r\nHost: ",
      target,
      "\r\n",
      proxy_authorization(proxy.userinfo),
      "\r\n"
    ]
  end

  defp proxy_authorization(nil), do: []

  defp proxy_authorization(userinfo) do
    ["Proxy-Authorization: Basic ", Base.encode64(URI.decode(userinfo)), "\r\n"]
  end

  defp tls_options(state) do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: String.to_charlist(state.endpoint.host),
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"]
    ]
    |> Keyword.merge(state.tls_options)
    |> Keyword.put(:mode, :binary)
    |> Keyword.put(:packet, :raw)
    |> Keyword.put(:active, false)
    |> Keyword.put(:nodelay, true)
  end

  defp receive_http_upgrade(socket, timeout),
    do: receive_http_upgrade(socket, "", 0, timeout)

  defp receive_http_upgrade(_socket, buffer, _scanned, _timeout)
       when byte_size(buffer) > @max_http_head_bytes,
       do: {:error, :http_head_too_large}

  defp receive_http_upgrade(socket, buffer, scanned, timeout) do
    # Rescan only the bytes that could hold a terminator straddling the
    # previous read boundary, keeping incremental reads linear.
    start = max(0, scanned - 3)

    case :binary.match(buffer, "\r\n\r\n", scope: {start, byte_size(buffer) - start}) do
      {head_length, 4} ->
        <<head::binary-size(^head_length), "\r\n\r\n", read_ahead::binary>> = buffer

        case :binary.split(head, "\r\n") do
          [status_line, _rest] -> validate_switching_protocols(status_line, read_ahead)
          [status_line] -> validate_switching_protocols(status_line, read_ahead)
        end

      :nomatch ->
        case socket_recv(socket, timeout) do
          {:ok, data} -> receive_http_upgrade(socket, buffer <> data, byte_size(buffer), timeout)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp validate_switching_protocols(status_line, read_ahead) do
    case :binary.split(status_line, " ", [:global]) do
      [version, "101" | _rest] when version in ["HTTP/1.0", "HTTP/1.1"] ->
        {:ok, read_ahead}

      _other ->
        {:error, {:http_status, status_line}}
    end
  end

  defp receive_frame(socket, buffer, timeout) do
    with {:ok, buffer} <- ensure_bytes(socket, buffer, Frame.header_length(), timeout),
         {:ok, type, length, _rest} <- Frame.decode_header(buffer),
         true <- length <= @max_server_frame_bytes,
         {:ok, buffer} <-
           ensure_bytes(socket, buffer, Frame.header_length() + length, timeout) do
      <<_header::binary-size(5), payload::binary-size(^length), rest::binary>> = buffer
      {:ok, type, payload, rest}
    else
      false -> {:error, :server_frame_too_large}
      {:error, _reason} = error -> error
    end
  end

  defp ensure_bytes(_socket, buffer, wanted, _timeout) when byte_size(buffer) >= wanted,
    do: {:ok, buffer}

  defp ensure_bytes(socket, buffer, wanted, timeout) do
    case socket_recv(socket, timeout) do
      {:ok, data} -> ensure_bytes(socket, buffer <> data, wanted, timeout)
      {:error, reason} -> {:error, reason}
    end
  end

  defp upgrade_request(endpoint) do
    [
      "GET ",
      endpoint.path,
      " HTTP/1.1\r\nHost: ",
      endpoint.host_header,
      "\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
    ]
  end

  defp parse_endpoint(url) when is_binary(url) do
    uri = URI.parse(url)

    with scheme when scheme in ["http", "https"] <- uri.scheme,
         host when is_binary(host) and host != "" <- uri.host,
         port when port in 1..65_535 <- uri.port do
      default_port = if scheme == "https", do: 443, else: 80
      authority_host = if String.contains?(host, ":"), do: "[#{host}]", else: host

      host_header =
        if port == default_port, do: authority_host, else: "#{authority_host}:#{port}"

      {:ok,
       %{
         scheme: scheme,
         host: host,
         dial_host: host,
         host_header: host_header,
         port: port,
         path: if(uri.path in [nil, ""], do: "/derp", else: uri.path)
       }}
    else
      _invalid -> {:error, :invalid_url}
    end
  end

  defp parse_endpoint(_url), do: {:error, :invalid_url}

  defp parse_proxy(nil), do: {:ok, nil}

  defp parse_proxy(url) when is_binary(url) do
    uri = URI.parse(url)

    with "http" <- uri.scheme,
         host when is_binary(host) and host != "" <- uri.host,
         port when port in 1..65_535 <- uri.port do
      {:ok, %{host: host, port: port, userinfo: uri.userinfo}}
    else
      _invalid -> {:error, :invalid_proxy_url}
    end
  end

  defp parse_proxy(_url), do: {:error, :invalid_proxy_url}

  defp host_and_port(host, port) do
    if String.contains?(host, ":"), do: "[#{host}]:#{port}", else: "#{host}:#{port}"
  end

  defp socket_send({:tcp, socket}, data), do: :gen_tcp.send(socket, data)
  defp socket_send({:ssl, socket}, data), do: :ssl.send(socket, data)

  defp socket_recv({:tcp, socket}, timeout), do: :gen_tcp.recv(socket, 0, timeout)
  defp socket_recv({:ssl, socket}, timeout), do: :ssl.recv(socket, 0, timeout)

  defp active_once({:tcp, socket}), do: :inet.setopts(socket, active: :once)
  defp active_once({:ssl, socket}), do: :ssl.setopts(socket, active: :once)

  defp cache_local_address({:tcp, socket}) do
    case :inet.sockname(socket) do
      {:ok, address} ->
        ClientAddressTable.put(self(), address)
        :ok

      {:error, reason} ->
        {:error, {:local_address, reason}}
    end
  end

  defp cache_local_address({:ssl, socket}) do
    case :ssl.sockname(socket) do
      {:ok, address} ->
        ClientAddressTable.put(self(), address)
        :ok

      {:error, reason} ->
        {:error, {:local_address, reason}}
    end
  end

  defp close_socket(nil), do: :ok
  defp close_socket({:tcp, socket}), do: :gen_tcp.close(socket)
  defp close_socket({:ssl, socket}), do: :ssl.close(socket)

  defp dispatch_event(state, event) do
    _result = state.event_handler.(event)
    :ok
  end

  defp positive_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a positive integer"
    end
  end

  defp non_negative_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value >= 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a non-negative integer"
    end
  end
end
