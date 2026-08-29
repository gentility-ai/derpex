defmodule Derpex.Listener.Handler do
  @moduledoc false

  use ThousandIsland.Handler

  require Logger

  alias Derpex.AcceptLimiter
  alias Derpex.Admission
  alias Derpex.Admission.Request, as: AdmissionRequest
  alias Derpex.ClientVerifier
  alias Derpex.Clock
  alias Derpex.Debug.Traffic
  alias Derpex.Disco
  alias Derpex.Drain
  alias Derpex.Metrics
  alias Derpex.Outbox.Ring
  alias Derpex.RateConfig
  alias Derpex.RateController
  alias Derpex.RateLimiter
  alias Derpex.ReceiveLimiter
  alias Derpex.Router
  alias Derpex.SendQueueConfig
  alias Derpex.Session
  alias Derpex.SocketOptions
  alias Derpex.TCPInfo
  alias Derpex.Transport.ThousandIsland, as: Transport
  alias Derpex.WebSocket.Frame, as: WebSocketFrame
  alias Derpex.Writer

  @impl ThousandIsland.Handler
  def handle_connection(socket, options) do
    private_key = Keyword.fetch!(options, :server_private_key)
    server_public_key = Keyword.fetch!(options, :server_public_key)
    mesh_key = Keyword.get(options, :mesh_key)
    server_info = Keyword.get(options, :server_info)
    admission_policy = Keyword.get(options, :admission)
    accept_limiter = Keyword.get(options, :accept_limiter, AcceptLimiter)
    rate_controller = Keyword.get(options, :rate_controller, RateController)
    bootstrap_dns = Keyword.get(options, :bootstrap_dns, Derpex.BootstrapDNS)
    drain = Keyword.get(options, :drain, Drain)
    metrics = Keyword.get_lazy(options, :metrics, &Metrics.default_handle/0)
    home_page = Keyword.get(options, :home_page, [])
    operations = Keyword.get(options, :operations, [])
    tcp_rtt_options = Keyword.get(options, :tcp_rtt, [])
    remote_address = remote_address(socket)

    debug =
      options
      |> Keyword.get(:debug, [])
      |> Keyword.put(:remote_ip, elem(remote_address, 0))

    disallowed_app_names =
      options
      |> Keyword.get(:disallowed_app_names, [])
      |> MapSet.new()

    event_handler = Keyword.get(options, :event_handler, fn _event -> :ok end)

    send_queue_depth =
      options
      |> Keyword.get(:send_queue_depth, SendQueueConfig.default_depth())
      |> SendQueueConfig.validate!()

    with :ok <- AcceptLimiter.claim(accept_limiter, elem(remote_address, 0)),
         {:ok, writer} <-
           Writer.start_link(
             owner: self(),
             transport: Transport,
             socket: socket,
             metrics: metrics
           ),
         ordinary =
           Ring.new(send_queue_depth,
             notifier: writer,
             wake_message: Writer.wake_message(),
             metrics: metrics,
             metric_kind: :other
           ),
         disco =
           Ring.new(send_queue_depth,
             notifier: writer,
             wake_message: Writer.wake_message(),
             metrics: metrics,
             metric_kind: :disco
           ),
         pong =
           Ring.new(1, notifier: writer, wake_message: Writer.wake_message()),
         lifecycle =
           Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
         :ok <-
           Writer.attach(writer, %{
             ordinary: ordinary,
             disco: disco,
             pong: pong,
             lifecycle: lifecycle
           }),
         {:ok, session, actions} <-
           Session.new(
             private_key,
             [mesh_key: mesh_key, server_info: server_info]
             |> Keyword.merge(
               bootstrap_dns: bootstrap_dns,
               home_page: home_page,
               operations: operations,
               debug: debug,
               remote_address: format_remote_address(remote_address)
             )
             |> Enum.reject(fn {_key, value} -> is_nil(value) end)
           ) do
      state = %{
        session: session,
        timers: %{},
        event_handler: event_handler,
        writer: writer,
        ordinary: ordinary,
        disco: disco,
        pong: pong,
        lifecycle: lifecycle,
        peer_gone_limiter: RateLimiter.new(1, 3),
        wire_mode: :native,
        websocket_decoder: WebSocketFrame.new(),
        client_public_key: nil,
        client_info: nil,
        can_mesh: false,
        preferred: false,
        connected_at: Clock.monotonic_time(:millisecond),
        admission_policy: admission_policy,
        admission_context: %{},
        client_verifier: Keyword.get(options, :client_verifier),
        disallowed_app_names: disallowed_app_names,
        rate_controller: rate_controller,
        receive_limiter: nil,
        server_public_key: server_public_key,
        remote_address: remote_address,
        accept_limiter: accept_limiter,
        drain: drain,
        metrics: metrics,
        mesh_write_timeout:
          Keyword.get(
            options,
            :mesh_write_timeout,
            SocketOptions.mesh_write_timeout_ms()
          ),
        debug_traffic: nil,
        tcp_rtt: nil,
        tcp_rtt_options: tcp_rtt_options
      }

      continue_after_actions(socket, state, actions)
    else
      {:error, reason}
      when reason in [
             :accept_rate_limited,
             :ip_rate_limited,
             :ip_connection_limited,
             :overflow_limited
           ] ->
        :ok = AcceptLimiter.release(accept_limiter)
        {:close, %{session: nil, timers: %{}, event_handler: event_handler}}

      {:error, reason} ->
        :ok = AcceptLimiter.release(accept_limiter)
        {:error, reason, %{session: nil, timers: %{}, event_handler: event_handler}}
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(data, socket, %{wire_mode: :websocket} = state) do
    case receive_websocket_data(socket, state, data) do
      {:ok, state} -> {:continue, state}
      {:close, state} -> {:close, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  def handle_data(data, socket, state) do
    case Session.receive_data(state.session, data) do
      {:ok, session, actions} ->
        continue_after_actions(socket, %{state | session: session}, actions)

      {:close, session, _reason, actions} ->
        close_after_actions(socket, %{state | session: session}, actions)
    end
  end

  @impl GenServer
  def handle_info({RateController, :updated, config}, {socket, state}) do
    {:noreply, {socket, put_receive_limiter(state, config)}}
  end

  def handle_info(
        {:derpex_close_peer, key},
        {socket, %{client_public_key: key} = state}
      ) do
    {:stop, {:shutdown, :close_peer}, {socket, state}}
  end

  def handle_info({:derpex_close_peer, _key}, {socket, state}) do
    {:noreply, {socket, state}}
  end

  def handle_info({:derpex_admission_close, reason}, {socket, state}) do
    {:stop, {:shutdown, {:admission, reason}}, {socket, state}}
  end

  def handle_info({:derpex_drain_close, _token}, {socket, state}) do
    {:stop, {:shutdown, :drain_deadline}, {socket, state}}
  end

  def handle_info({:derpex_timeout, name, token}, {socket, state}) do
    case state.timers[name] do
      {^token, _timer} -> handle_protocol_timeout(socket, state, name)
      _stale -> {:noreply, {socket, state}}
    end
  end

  def handle_info(:derpex_debug_traffic_tick, {socket, %{debug_traffic: nil} = state}) do
    {:noreply, {socket, state}}
  end

  def handle_info(:derpex_debug_traffic_tick, {socket, state}) do
    debug = %{state.debug_traffic | timer: nil}

    case Traffic.sample(debug.previous, debug.options) do
      {:ok, current, body} ->
        case Writer.write_control(state.writer, encode_chunk(body)) do
          :ok ->
            timer =
              Clock.send_after(self(), :derpex_debug_traffic_tick, debug.interval_ms)

            debug = %{debug | previous: current, timer: timer}
            {:noreply, {socket, %{state | debug_traffic: debug}}}

          {:error, reason} ->
            {:stop, {:debug_traffic_write, reason}, {socket, state}}
        end

      {:error, reason} ->
        error_body = ["ss failed: ", debug_error(reason)]
        terminal = [encode_chunk(error_body), "0\r\n\r\n"]

        case Writer.write_control(state.writer, terminal) do
          :ok -> {:stop, {:shutdown, :debug_traffic_complete}, {socket, state}}
          {:error, write_reason} -> {:stop, {:debug_traffic_write, write_reason}, {socket, state}}
        end
    end
  end

  def handle_info(:derpex_tcp_rtt_tick, {socket, %{tcp_rtt: nil} = state}) do
    {:noreply, {socket, state}}
  end

  def handle_info(:derpex_tcp_rtt_tick, {socket, state}) do
    tcp_rtt = %{state.tcp_rtt | timer: nil}

    case TCPInfo.rtt_microseconds(socket, tcp_rtt.options) do
      {:ok, microseconds} -> :ok = Metrics.observe_tcp_rtt(state.metrics, microseconds)
      {:error, _reason} -> :ok
    end

    timer = Clock.send_after(self(), :derpex_tcp_rtt_tick, tcp_rtt.interval_ms)
    tcp_rtt = %{tcp_rtt | timer: timer}
    {:noreply, {socket, %{state | tcp_rtt: tcp_rtt}}}
  end

  @impl ThousandIsland.Handler
  def handle_close(_socket, state), do: cleanup(state)

  @impl ThousandIsland.Handler
  def handle_error(_reason, _socket, state), do: cleanup(state)

  @impl ThousandIsland.Handler
  def handle_shutdown(_socket, state), do: cleanup(state)

  defp handle_protocol_timeout(socket, state, name) do
    state = %{state | timers: Map.delete(state.timers, name)}

    case Session.timeout(state.session, name) do
      {:ok, session, actions} ->
        case execute_actions(socket, %{state | session: session}, actions) do
          {:ok, state} -> {:noreply, {socket, state}}
          {:error, reason, state} -> {:stop, reason, {socket, state}}
        end

      {:close, session, reason, actions} ->
        state = %{state | session: session}

        case execute_actions(socket, state, actions) do
          {:ok, state} -> {:stop, {:shutdown, reason}, {socket, state}}
          {:error, send_reason, state} -> {:stop, send_reason, {socket, state}}
        end
    end
  end

  defp continue_after_actions(socket, state, actions) do
    case execute_actions(socket, state, actions) do
      {:ok, state} -> {:continue, state}
      {:error, reason, state} -> close_or_error(reason, state)
    end
  end

  # Shedding for a full usage spool is a capacity decision, not a fault: the
  # connection closes cleanly and the drop is counted by admission. Any other
  # usage failure is a fault worth a line in the log, but it still closes the
  # connection rather than crash-reporting it.
  defp close_or_error({kind, _reason}, state)
       when kind in [:admission, :connection_close],
       do: {:close, state}

  defp close_or_error({:usage, :usage_spool_full}, state), do: {:close, state}
  defp close_or_error({:rate_limit, :usage_spool_full}, state), do: {:close, state}

  defp close_or_error({:usage, reason}, state) do
    Logger.warning("closing a connection after a usage-accounting failure: #{inspect(reason)}")
    {:close, state}
  end

  defp close_or_error(reason, state), do: {:error, reason, state}

  defp close_after_actions(socket, state, actions) do
    case execute_actions(socket, state, actions) do
      {:ok, state} -> {:close, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp execute_actions(socket, state, actions) do
    Enum.reduce_while(actions, {:ok, state}, fn action, {:ok, state} ->
      case execute_action(socket, state, action) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason, state} -> {:halt, {:error, reason, state}}
      end
    end)
  end

  defp execute_action(_socket, state, {:send, data}) do
    case Writer.write_control(state.writer, data) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, {:send, reason}, state}
    end
  end

  defp execute_action(_socket, state, {:set_timeout, name, milliseconds}) do
    state = cancel_timer(state, name)
    token = make_ref()
    timer = Clock.send_after(self(), {:derpex_timeout, name, token}, milliseconds)
    {:ok, %{state | timers: Map.put(state.timers, name, {token, timer})}}
  end

  defp execute_action(_socket, state, {:cancel_timeout, name}) do
    {:ok, cancel_timer(state, name)}
  end

  defp execute_action(_socket, state, {:start_debug_traffic, options}) do
    interval_ms = Keyword.get(options, :interval_ms, 2_000)

    if is_integer(interval_ms) and interval_ms > 0 do
      send(self(), :derpex_debug_traffic_tick)

      debug = %{previous: %{}, options: options, interval_ms: interval_ms, timer: nil}
      {:ok, %{state | debug_traffic: debug}}
    else
      {:error, :invalid_debug_traffic_interval, state}
    end
  end

  defp execute_action(socket, state, {:rate_limit, frame_length}) do
    rate_limit(socket, state, frame_length)
  end

  defp execute_action(socket, state, {:authenticated, key, info, can_mesh}) do
    if can_mesh do
      _ignored =
        SocketOptions.configure_mesh_write_timeout(socket, state.mesh_write_timeout)
    end

    case admit(state, key, info, can_mesh) do
      {:ok, {admission_context, request}} ->
        claim_and_register(socket, state, key, info, can_mesh, request, admission_context)

      {:error, reason} ->
        {:error, {:admission, reason}, state}
    end
  end

  defp execute_action(_socket, state, {:client_message, message}) do
    with {:ok, state} <- handle_client_message(state, message) do
      dispatch_event(state, {:client_message, message})
    end
  end

  defp execute_action(_socket, state, :activity) do
    :ok = Router.note_activity(state.client_public_key, self())
    {:ok, state}
  end

  defp execute_action(_socket, state, {:server_message, message}) do
    _enqueue_result = Ring.enqueue(state.lifecycle, message)
    {:ok, state}
  end

  defp execute_action(_socket, state, {:set_wire_mode, :websocket}) do
    :ok = Writer.set_wire_mode(state.writer, :websocket)
    {:ok, %{state | wire_mode: :websocket}}
  end

  defp execute_action(socket, state, {:websocket_data, data}) do
    case receive_websocket_data(socket, state, data) do
      {:ok, state} -> {:ok, state}
      {:close, state} -> {:error, :websocket_closed, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp dispatch_event(state, event) do
    case state.event_handler.(event) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, {:event_handler, reason}, state}
    end
  end

  defp cancel_timer(state, name) do
    case Map.pop(state.timers, name) do
      {nil, timers} ->
        %{state | timers: timers}

      {{_token, timer}, timers} ->
        _remaining = Clock.cancel_timer(timer)
        %{state | timers: timers}
    end
  end

  defp cancel_all_timers(%{timers: timers}) do
    Enum.each(timers, fn {_name, {_token, timer}} -> Clock.cancel_timer(timer) end)
    :ok
  end

  defp handle_client_message(state, {:send_packet, destination, packet}) do
    :ok = Metrics.add(state.metrics, :packets_received, 1)
    :ok = Metrics.add(state.metrics, :bytes_received, byte_size(packet))

    packet_kind =
      if Disco.looks_like_wrapper?(packet),
        do: :packets_received_disco,
        else: :packets_received_other

    :ok = Metrics.add(state.metrics, packet_kind, 1)
    route_result = Router.route(state.client_public_key, destination, packet)

    with {:ok, state} <- handle_route_result(state, destination, packet, route_result),
         :ok <-
           Admission.record_usage(
             state.admission_policy,
             state.admission_context,
             byte_size(packet),
             usage_outcome(route_result)
           ) do
      {:ok, state}
    else
      {:error, reason} -> {:error, {:usage, reason}, state}
    end
  end

  defp handle_client_message(state, {:ping, payload}) do
    :ok = Metrics.add(state.metrics, :got_ping, 1)
    _enqueue_result = Ring.enqueue(state.pong, {:pong, payload})
    {:ok, state}
  end

  defp handle_client_message(state, {:note_preferred, preferred}) do
    case Drain.set_preferred(state.drain, self(), preferred) do
      :ok ->
        state = record_home_move(state, preferred)
        {:ok, %{state | preferred: preferred}}

      {:error, :draining} ->
        {:error, {:connection_close, :draining}, state}
    end
  end

  defp handle_client_message(
         %{can_mesh: true} = state,
         {:forward_packet, source, destination, packet}
       ) do
    :ok = Metrics.add(state.metrics, :packets_forwarded_in, 1)

    case Router.route_local(source, destination, packet) do
      {:dropped, :unknown_destination} ->
        :ok =
          Metrics.add_drop(
            state.metrics,
            :unknown_dest_on_fwd,
            packet_kind(packet),
            byte_size(packet)
          )

        maybe_notify_unknown_destination(state, destination, packet)

      _routed_or_queue_drop ->
        {:ok, state}
    end
  end

  defp handle_client_message(%{can_mesh: true} = state, {:close_peer, key}) do
    _closed_connection_count = Router.close_peer(key)
    {:ok, state}
  end

  defp handle_client_message(state, message)
       when elem(message, 0) in [:forward_packet, :close_peer] do
    {:error, :insufficient_permissions, state}
  end

  defp handle_client_message(%{can_mesh: true} = state, :watch_connections) do
    if state.client_public_key != state.server_public_key do
      :ok = Router.watch(self(), state.lifecycle)
    end

    {:ok, state}
  end

  defp handle_client_message(state, :watch_connections),
    do: {:error, :insufficient_permissions, state}

  defp handle_client_message(state, _message), do: {:ok, state}

  defp handle_route_result(state, destination, packet, {:dropped, :unknown_destination}) do
    :ok = Metrics.add_drop(state.metrics, :unknown_dest, packet_kind(packet), byte_size(packet))
    maybe_notify_unknown_destination(state, destination, packet)
  end

  defp handle_route_result(state, _destination, _packet, _result), do: {:ok, state}

  defp usage_outcome({:ok, _result}), do: :accepted
  defp usage_outcome({:dropped, _reason}), do: :dropped

  defp packet_kind(packet) do
    if Disco.looks_like_wrapper?(packet), do: :disco, else: :other
  end

  defp maybe_notify_unknown_destination(state, destination, packet) do
    if Derpex.Disco.looks_like_wrapper?(packet) do
      {allowed?, limiter} = RateLimiter.allow(state.peer_gone_limiter)
      state = %{state | peer_gone_limiter: limiter}

      if allowed? do
        _enqueue_result = Ring.enqueue(state.lifecycle, {:peer_gone, destination, 0x01})
      end

      {:ok, state}
    else
      {:ok, state}
    end
  end

  defp receive_websocket_data(socket, state, data) do
    case WebSocketFrame.push(state.websocket_decoder, data) do
      {:ok, events, decoder} ->
        process_websocket_events(socket, %{state | websocket_decoder: decoder}, events)

      {:error, reason} ->
        {:error, {:websocket, reason}, state}
    end
  end

  defp process_websocket_events(_socket, state, []), do: {:ok, state}

  defp process_websocket_events(socket, state, [{:binary, data} | rest]) do
    case Session.receive_data(state.session, data) do
      {:ok, session, actions} ->
        case execute_actions(socket, %{state | session: session}, actions) do
          {:ok, state} -> process_websocket_events(socket, state, rest)
          {:error, reason, state} -> close_or_error(reason, state)
        end

      {:close, session, _reason, actions} ->
        case execute_actions(socket, %{state | session: session}, actions) do
          {:ok, state} -> {:close, state}
          {:error, reason, state} -> {:error, reason, state}
        end
    end
  end

  defp process_websocket_events(socket, state, [{:ping, payload} | rest]) do
    case Writer.websocket_pong(state.writer, payload) do
      :ok -> process_websocket_events(socket, state, rest)
      {:error, reason} -> {:error, {:websocket_pong, reason}, state}
    end
  end

  defp process_websocket_events(socket, state, [{:pong, _payload} | rest]),
    do: process_websocket_events(socket, state, rest)

  defp process_websocket_events(_socket, state, [{:close, _payload} | _rest]),
    do: {:close, state}

  defp cleanup(%{timers: _timers} = state) do
    cancel_all_timers(state)
    cancel_debug_traffic_timer(state[:debug_traffic])
    cancel_tcp_rtt_timer(state[:tcp_rtt])
    :ok = AcceptLimiter.release(state[:accept_limiter])
    :ok = Drain.unregister(state[:drain], self())
    :ok = Admission.release(state[:admission_policy], self())

    if state[:client_public_key] && Process.whereis(Router) do
      Router.unregister(state.client_public_key, self())
    end

    close_ring(state[:ordinary])
    close_ring(state[:disco])
    close_ring(state[:pong])
    close_ring(state[:lifecycle])
    :ok
  end

  defp cleanup(_pre_connection_options), do: :ok

  defp close_ring(%Ring{} = ring) do
    _result = Ring.close(ring)
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp close_ring(_ring), do: :ok

  defp cancel_debug_traffic_timer(%{timer: timer}) when is_reference(timer) do
    _remaining = Clock.cancel_timer(timer)
    :ok
  end

  defp cancel_debug_traffic_timer(_debug), do: :ok

  defp cancel_tcp_rtt_timer(%{timer: timer}) when is_reference(timer) do
    _remaining = Clock.cancel_timer(timer)
    :ok
  end

  defp cancel_tcp_rtt_timer(_tcp_rtt), do: :ok

  defp encode_chunk(data) do
    [Integer.to_string(IO.iodata_length(data), 16), "\r\n", data, "\r\n"]
  end

  defp debug_error(reason) when is_binary(reason), do: reason
  defp debug_error(reason), do: inspect(reason)

  defp maybe_start_tcp_rtt(_socket, %{tcp_rtt_options: false} = state), do: state

  defp maybe_start_tcp_rtt(socket, state) do
    options = state.tcp_rtt_options

    if TCPInfo.supported?(options) do
      initialize_tcp_rtt(socket, state, options)
    else
      state
    end
  end

  defp initialize_tcp_rtt(socket, state, options) do
    case TCPInfo.rtt_microseconds(socket, options) do
      {:ok, _microseconds} ->
        interval_ms = Keyword.get(options, :interval_ms, 10_000)
        timer = Clock.send_after(self(), :derpex_tcp_rtt_tick, interval_ms)
        %{state | tcp_rtt: %{options: options, interval_ms: interval_ms, timer: timer}}

      {:error, :not_tcp} ->
        :ok = Metrics.observe_tcp_rtt(state.metrics, :non_tcp)
        state

      {:error, _reason} ->
        :ok = Metrics.observe_tcp_rtt(state.metrics, :error)
        state
    end
  end

  defp claim_and_register(socket, state, key, info, can_mesh, request, admission_context) do
    case Admission.claim(state.admission_policy, request, admission_context, self()) do
      {:ok, admission_context} ->
        with {:ok, state} <-
               register_authenticated(state, key, info, can_mesh, admission_context) do
          {:ok, maybe_start_tcp_rtt(socket, state)}
        end

      {:error, reason} ->
        {:error, {:admission, reason}, state}
    end
  end

  defp admit(state, key, info, can_mesh) do
    request = %AdmissionRequest{
      node_key: key,
      client_info: info,
      source_ip: elem(state.remote_address, 0),
      mesh_peer?: can_mesh,
      metadata: Session.info(state.session).metadata
    }

    with :ok <- app_name_allowed(state.disallowed_app_names, request),
         :ok <- ClientVerifier.verify(state.client_verifier, request),
         {:ok, context} <- Admission.authorize(state.admission_policy, request) do
      {:ok, {context, request}}
    end
  end

  defp app_name_allowed(_disallowed, %AdmissionRequest{mesh_peer?: true}), do: :ok

  defp app_name_allowed(disallowed, %AdmissionRequest{client_info: info}) do
    if MapSet.member?(disallowed, info.app_name) do
      {:error, {:disallowed_app_name, info.app_name}}
    else
      :ok
    end
  end

  defp register_authenticated(state, key, info, can_mesh, admission_context) do
    presence = presence(state, info, can_mesh)
    state = subscribe_to_rate_config(state, can_mesh)

    :ok =
      Router.register(
        key,
        self(),
        state.ordinary,
        state.disco,
        state.lifecycle,
        presence
      )

    :ok = Drain.register(state.drain, self(), state.lifecycle, can_mesh)
    :ok = Metrics.add(state.metrics, :accepts, 1)

    state
    |> Map.put(:client_public_key, key)
    |> Map.put(:client_info, info)
    |> Map.put(:can_mesh, can_mesh)
    |> Map.put(:admission_context, admission_context)
    |> dispatch_event({:authenticated, key, info})
  end

  defp record_home_move(%{preferred: preferred} = state, preferred), do: state

  defp record_home_move(state, preferred) do
    if Clock.monotonic_time(:millisecond) - state.connected_at > 5_000 do
      metric = if preferred, do: :home_moves_in, else: :home_moves_out
      :ok = Metrics.add(state.metrics, metric, 1)
    end

    state
  end

  defp subscribe_to_rate_config(%{rate_controller: nil} = state, _can_mesh), do: state

  defp subscribe_to_rate_config(state, can_mesh) do
    config = RateController.subscribe(state.rate_controller, self(), can_mesh)
    put_receive_limiter(state, config)
  end

  defp put_receive_limiter(state, %RateConfig{per_client_rate_limit_bytes_per_second: 0}) do
    %{state | receive_limiter: nil}
  end

  defp put_receive_limiter(state, %RateConfig{} = config) do
    %{state | receive_limiter: ReceiveLimiter.new(config)}
  end

  defp rate_limit(socket, state, frame_length) do
    with {:ok, admission_delay} <-
           Admission.reserve_bytes(
             state.admission_policy,
             state.admission_context,
             frame_length
           ),
         {:ok, receive_delay, state} <- reserve_receive_bytes(state, frame_length),
         :ok <- wait_for_rate_limit(socket, max(admission_delay, receive_delay)) do
      {:ok, state}
    else
      {:error, reason, state} -> {:error, {:rate_limit, reason}, state}
      {:error, {:connection_close, _reason} = reason} -> {:error, reason, state}
      {:error, reason} -> {:error, {:rate_limit, reason}, state}
    end
  end

  defp reserve_receive_bytes(%{receive_limiter: nil} = state, _frame_length),
    do: {:ok, 0, state}

  defp reserve_receive_bytes(state, frame_length) do
    case ReceiveLimiter.reserve(state.receive_limiter, frame_length) do
      {:ok, delay_microseconds, limiter} ->
        {:ok, delay_microseconds, %{state | receive_limiter: limiter}}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp wait_for_rate_limit(_socket, 0), do: :ok

  defp wait_for_rate_limit(socket, delay_microseconds) do
    token = make_ref()
    milliseconds = max(div(delay_microseconds + 999, 1_000), 1)
    timer = Clock.send_after(self(), {:derpex_rate_limit_ready, token}, milliseconds)
    raw_socket = socket.socket

    receive do
      {:derpex_rate_limit_ready, ^token} ->
        :ok

      {:tcp_closed, ^raw_socket} ->
        _remaining = Clock.cancel_timer(timer)
        {:error, :peer_closed}

      {:ssl_closed, ^raw_socket} ->
        _remaining = Clock.cancel_timer(timer)
        {:error, :peer_closed}

      {:derpex_close_peer, _key} ->
        _remaining = Clock.cancel_timer(timer)
        {:error, {:connection_close, :close_peer}}

      {:derpex_admission_close, reason} ->
        _remaining = Clock.cancel_timer(timer)
        {:error, {:connection_close, {:admission, reason}}}

      {:EXIT, _process, reason} ->
        _remaining = Clock.cancel_timer(timer)
        {:error, {:shutdown, reason}}
    end
  end

  defp remote_address(socket) do
    case Transport.peername(socket) do
      {:ok, {ip, port}} -> {ip, port}
      {:error, _reason} -> {{0, 0, 0, 0}, 0}
    end
  end

  defp format_remote_address({ip, port}) do
    address = ip |> :inet.ntoa() |> List.to_string()
    if tuple_size(ip) == 8, do: "[#{address}]:#{port}", else: "#{address}:#{port}"
  end

  defp presence(state, info, can_mesh) do
    {ip, port} = state.remote_address

    %{
      ip: encode_ip(ip),
      port: port,
      flags: presence_flags(info, can_mesh, state.session),
      app_name: info.app_name
    }
  end

  defp encode_ip({a, b, c, d}), do: <<0::80, 0xFFFF::16, a, b, c, d>>

  defp encode_ip({a, b, c, d, e, f, g, h}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

  defp presence_flags(info, can_mesh, session) do
    flags =
      0
      |> maybe_flag(info.is_prober, 0x04)
      |> maybe_flag(can_mesh, 0x02)
      |> maybe_flag(not_ideal?(session), 0x08)

    if flags == 0, do: 0x01, else: flags
  end

  defp maybe_flag(flags, true, flag), do: Bitwise.bor(flags, flag)
  defp maybe_flag(flags, false, _flag), do: flags

  defp not_ideal?(session) do
    case Session.info(session).metadata.ideal_node do
      value when is_binary(value) -> value != ""
      nil -> false
    end
  end
end
