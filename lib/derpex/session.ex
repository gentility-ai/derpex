defmodule Derpex.Session do
  @moduledoc """
  Pure HTTP-to-DERP session state machine.

  It preserves bytes read ahead of the HTTP head and emits transport actions in
  wire order. Socket handlers execute the actions synchronously.
  """

  alias Derpex.Connection
  alias Derpex.Crypto
  alias Derpex.HTTP1
  alias Derpex.HTTP1.Parser

  @http_timeout 10_000

  defstruct [
    :phase,
    :server_private_key,
    :server_public_key,
    :http_parser,
    :connection_options,
    :connection,
    :metadata,
    :close_reason
  ]

  @type action ::
          Connection.action()
          | {:set_timeout, :http, pos_integer()}
          | {:cancel_timeout, :http}
          | {:set_wire_mode, :websocket}
          | {:websocket_data, binary()}
  @type phase :: :http | :derp | :closed

  @opaque t :: %__MODULE__{
            phase: phase(),
            server_private_key: binary(),
            server_public_key: binary(),
            http_parser: Parser.t(),
            connection_options: keyword(),
            connection: nil | Connection.t(),
            metadata: map(),
            close_reason: nil | term()
          }

  @doc "Creates a session waiting for one bounded HTTP request head."
  @spec new(binary(), keyword()) :: {:ok, t(), [action()]} | {:error, atom()}
  def new(server_private_key, options \\ []) do
    with {:ok, server_public_key} <- Crypto.public_key(server_private_key) do
      state = %__MODULE__{
        phase: :http,
        server_private_key: server_private_key,
        server_public_key: server_public_key,
        http_parser: Parser.new(Keyword.get(options, :http_parser, [])),
        connection_options: Keyword.take(options, [:mesh_key]),
        connection: nil,
        metadata: %{},
        close_reason: nil
      }

      {:ok, state, [{:set_timeout, :http, @http_timeout}]}
    end
  end

  @doc "Consumes bytes from a native byte-stream transport."
  @spec receive_data(t(), binary()) ::
          {:ok, t(), [action()]} | {:close, t(), term(), [action()]}
  def receive_data(%__MODULE__{phase: :closed} = state, _data),
    do: {:close, state, state.close_reason, []}

  def receive_data(%__MODULE__{phase: :http} = state, data), do: receive_http(state, data)

  def receive_data(%__MODULE__{phase: :derp} = state, data) do
    state.connection
    |> Connection.receive_data(data)
    |> map_connection_result(state)
  end

  @doc "Applies an HTTP or DERP handshake deadline."
  @spec timeout(t(), atom()) :: {:ok, t(), []} | {:close, t(), term(), []}
  def timeout(%__MODULE__{phase: :http} = state, :http), do: close(state, :http_timeout, [])

  def timeout(%__MODULE__{phase: :derp} = state, name) do
    state.connection
    |> Connection.timeout(name)
    |> map_connection_result(state)
  end

  def timeout(%__MODULE__{} = state, _name), do: {:ok, state, []}

  @doc "Returns externally useful session state."
  @spec info(t()) :: map()
  def info(%__MODULE__{} = state) do
    %{
      phase: state.phase,
      metadata: state.metadata,
      close_reason: state.close_reason,
      connection: if(state.connection, do: Connection.info(state.connection), else: nil)
    }
  end

  defp receive_http(state, data) do
    case Parser.push(state.http_parser, data) do
      {:more, parser} ->
        {:ok, %{state | http_parser: parser}, []}

      {:ok, request, read_ahead, parser} ->
        state = %{state | http_parser: parser}
        route_http(state, HTTP1.route(request, state.server_public_key), read_ahead)

      {:error, reason} ->
        close(state, reason, [])
    end
  end

  defp route_http(state, {:response, response}, _read_ahead) do
    close(state, :http_response, [{:cancel_timeout, :http}, {:send, response}])
  end

  defp route_http(state, {:upgrade, :websocket, response, metadata}, read_ahead) do
    with {:ok, connection, connection_actions} <-
           Connection.new(state.server_private_key, state.connection_options) do
      state = %{state | phase: :derp, connection: connection, metadata: metadata}

      actions =
        [{:cancel_timeout, :http}, {:send, response}, {:set_wire_mode, :websocket}] ++
          connection_actions ++ maybe_websocket_data(read_ahead)

      {:ok, state, actions}
    end
  end

  defp route_http(state, {:upgrade, :derp, response, metadata}, read_ahead) do
    with {:ok, connection, connection_actions} <-
           Connection.new(state.server_private_key, state.connection_options) do
      state = %{state | phase: :derp, connection: connection, metadata: metadata}
      actions = [{:cancel_timeout, :http}] ++ maybe_send(response) ++ connection_actions
      receive_read_ahead(state, read_ahead, actions)
    end
  end

  defp receive_read_ahead(state, "", actions), do: {:ok, state, actions}

  defp receive_read_ahead(state, read_ahead, actions) do
    case Connection.receive_data(state.connection, read_ahead) do
      {:ok, connection, read_ahead_actions} ->
        {:ok, %{state | connection: connection}, actions ++ read_ahead_actions}

      {:close, connection, reason, read_ahead_actions} ->
        close(%{state | connection: connection}, reason, actions ++ read_ahead_actions)
    end
  end

  defp map_connection_result({:ok, connection, actions}, state) do
    {:ok, %{state | connection: connection}, actions}
  end

  defp map_connection_result({:close, connection, reason, actions}, state) do
    close(%{state | connection: connection}, reason, actions)
  end

  defp maybe_send(nil), do: []
  defp maybe_send(response), do: [{:send, response}]

  defp maybe_websocket_data(""), do: []
  defp maybe_websocket_data(data), do: [{:websocket_data, data}]

  defp close(state, reason, actions) do
    state = %{state | phase: :closed, close_reason: reason}
    {:close, state, reason, actions}
  end
end
