defmodule Derpex.Listener.Handler do
  @moduledoc false

  use ThousandIsland.Handler

  alias Derpex.Admission
  alias Derpex.Admission.Request, as: AdmissionRequest
  alias Derpex.Clock
  alias Derpex.Crypto
  alias Derpex.Outbox.Ring
  alias Derpex.RateLimiter
  alias Derpex.Router
  alias Derpex.Session
  alias Derpex.Transport.ThousandIsland, as: Transport
  alias Derpex.WebSocket.Frame, as: WebSocketFrame
  alias Derpex.Writer

  @impl ThousandIsland.Handler
  def handle_connection(socket, options) do
    server_private_key = Keyword.fetch!(options, :server_private_key)
    mesh_key = Keyword.get(options, :mesh_key)
    admission_policy = Keyword.get(options, :admission)

    disallowed_app_names =
      options
      |> Keyword.get(:disallowed_app_names, [])
      |> MapSet.new()

    event_handler = Keyword.get(options, :event_handler, fn _event -> :ok end)

    with {:ok, server_public_key} <- Crypto.public_key(server_private_key),
         {:ok, writer} <- Writer.start_link(owner: self(), transport: Transport, socket: socket),
         ordinary =
           Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
         disco =
           Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
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
         {:ok, session, actions} <- Session.new(server_private_key, mesh_key: mesh_key) do
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
        admission_policy: admission_policy,
        admission_context: %{},
        disallowed_app_names: disallowed_app_names,
        server_public_key: server_public_key,
        remote_address: remote_address(socket)
      }

      continue_after_actions(socket, state, actions)
    else
      {:error, reason} ->
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
  def handle_info({:derpex_timeout, name, token}, {socket, state}) do
    case state.timers[name] do
      {^token, _timer} -> handle_protocol_timeout(socket, state, name)
      _stale -> {:noreply, {socket, state}}
    end
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
      {:error, {:admission, _reason}, state} -> {:close, state}
      {:error, reason, state} -> {:error, reason, state}
    end
  end

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

  defp execute_action(_socket, state, {:authenticated, key, info, can_mesh}) do
    case admit(state, key, info, can_mesh) do
      {:ok, admission_context} ->
        register_authenticated(state, key, info, can_mesh, admission_context)

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
    case Router.route(state.client_public_key, destination, packet) do
      {:dropped, :unknown_destination} ->
        maybe_notify_unknown_destination(state, destination, packet)

      _routed_or_queue_drop ->
        {:ok, state}
    end
  end

  defp handle_client_message(state, {:ping, payload}) do
    _enqueue_result = Ring.enqueue(state.pong, {:pong, payload})
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
          {:error, {:admission, _reason}, state} -> {:close, state}
          {:error, reason, state} -> {:error, reason, state}
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

    if state[:client_public_key] && Process.whereis(Router) do
      Router.unregister(state.client_public_key, self())
    end

    close_ring(state[:ordinary])
    close_ring(state[:disco])
    close_ring(state[:pong])
    close_ring(state[:lifecycle])
    :ok
  end

  defp close_ring(%Ring{} = ring) do
    _result = Ring.close(ring)
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp close_ring(_ring), do: :ok

  defp admit(state, key, info, can_mesh) do
    request = %AdmissionRequest{
      node_key: key,
      client_info: info,
      source_ip: elem(state.remote_address, 0),
      mesh_peer?: can_mesh,
      metadata: Session.info(state.session).metadata
    }

    with :ok <- app_name_allowed(state.disallowed_app_names, request) do
      Admission.authorize(state.admission_policy, request)
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

    :ok =
      Router.register(
        key,
        self(),
        state.ordinary,
        state.disco,
        state.lifecycle,
        presence
      )

    state
    |> Map.put(:client_public_key, key)
    |> Map.put(:client_info, info)
    |> Map.put(:can_mesh, can_mesh)
    |> Map.put(:admission_context, admission_context)
    |> dispatch_event({:authenticated, key, info})
  end

  defp remote_address(socket) do
    case Transport.peername(socket) do
      {:ok, {ip, port}} -> {ip, port}
      {:error, _reason} -> {{0, 0, 0, 0}, 0}
    end
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
