defmodule Derpex.Connection do
  @moduledoc """
  Pure protocol state machine for one DERP connection.

  Socket adapters execute returned actions in order. In particular,
  authentication/registration precedes server-info transmission, so packets
  cannot overtake handshake completion. No action sends packet data through a
  process mailbox; packet messages are consumed synchronously by the reader.
  """

  alias Derpex.ClientInfo
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Frame.Decoder
  alias Derpex.Handshake
  alias Derpex.MeshKey
  alias Derpex.ServerInfo

  @handshake_timeout 10_000
  @max_client_info_length 256 * 1_024

  defstruct [
    :server_private_key,
    :server_info,
    :decoder,
    :phase,
    :client_public_key,
    :client_info,
    :mesh_key,
    :can_mesh,
    :keep_alive_interval,
    :close_reason
  ]

  @type phase :: :awaiting_client_info | :authenticated | :closed
  @type action ::
          {:send, iodata()}
          | {:set_timeout, :handshake, pos_integer()}
          | {:cancel_timeout, :handshake}
          | {:authenticated, binary(), ClientInfo.t(), boolean()}
          | {:rate_limit, non_neg_integer()}
          | :activity
          | {:server_message, Body.server_message()}
          | {:client_message, Body.client_message()}

  @opaque t :: %__MODULE__{
            server_private_key: binary(),
            server_info: ServerInfo.t(),
            decoder: Decoder.t(),
            phase: phase(),
            client_public_key: nil | binary(),
            client_info: nil | ClientInfo.t(),
            mesh_key: nil | MeshKey.t(),
            can_mesh: boolean(),
            keep_alive_interval: pos_integer(),
            close_reason: nil | term()
          }

  @doc "Creates a connection and returns its greeting and handshake deadline actions."
  @spec new(binary(), keyword()) :: {:ok, t(), [action()]} | {:error, atom()}
  def new(server_private_key, options \\ []) do
    server_info =
      Keyword.get(options, :server_info, %ServerInfo{version: Handshake.protocol_version()})

    with {:ok, greeting} <- Handshake.server_key_frame(server_private_key) do
      state = %__MODULE__{
        server_private_key: server_private_key,
        server_info: server_info,
        decoder: Decoder.new(frame_policy: &handshake_frame_policy/2),
        phase: :awaiting_client_info,
        client_public_key: nil,
        client_info: nil,
        mesh_key: Keyword.get(options, :mesh_key),
        can_mesh: false,
        keep_alive_interval: 60_000 + keep_alive_jitter(options),
        close_reason: nil
      }

      {:ok, state, [{:send, greeting}, {:set_timeout, :handshake, @handshake_timeout}]}
    end
  end

  @doc "Consumes a byte-stream chunk and emits ordered synchronous actions."
  @spec receive_data(t(), binary()) ::
          {:ok, t(), [action()]} | {:close, t(), term(), [action()]}
  def receive_data(%__MODULE__{phase: :closed} = state, _chunk) do
    {:close, state, state.close_reason, []}
  end

  def receive_data(%__MODULE__{} = state, chunk) when is_binary(chunk) do
    case Decoder.push(state.decoder, chunk) do
      {:ok, frames, decoder} ->
        state
        |> Map.put(:decoder, decoder)
        |> process_frames(frames, [])

      {:error, reason} ->
        close(state, reason, [])
    end
  end

  @doc "Applies a named protocol deadline."
  @spec timeout(t(), atom()) :: {:ok, t(), []} | {:close, t(), atom(), []}
  def timeout(%__MODULE__{phase: :awaiting_client_info} = state, :handshake) do
    close(state, :handshake_timeout, [])
  end

  def timeout(%__MODULE__{phase: :authenticated} = state, :keep_alive) do
    {:ok, state,
     [
       {:server_message, :keep_alive},
       {:set_timeout, :keep_alive, state.keep_alive_interval}
     ]}
  end

  def timeout(%__MODULE__{} = state, _timeout), do: {:ok, state, []}

  @doc "Returns the current externally useful connection state."
  @spec info(t()) :: map()
  def info(%__MODULE__{} = state) do
    %{
      phase: state.phase,
      client_public_key: state.client_public_key,
      client_info: state.client_info,
      can_mesh: state.can_mesh,
      close_reason: state.close_reason
    }
  end

  defp process_frames(state, [], actions), do: {:ok, state, Enum.reverse(actions)}

  defp process_frames(%__MODULE__{phase: :awaiting_client_info} = state, [frame | rest], actions) do
    case authenticate(state, frame) do
      {:ok, state, handshake_actions} ->
        process_frames(state, rest, Enum.reverse(handshake_actions, actions))

      {:error, reason} ->
        close(state, reason, Enum.reverse(actions))
    end
  end

  defp process_frames(
         %__MODULE__{phase: :authenticated} = state,
         [{_type, {:discarded, length}} | rest],
         actions
       ) do
    process_frames(state, rest, [:activity, {:rate_limit, length} | actions])
  end

  defp process_frames(%__MODULE__{phase: :authenticated} = state, [frame | rest], actions) do
    case frame do
      buffered_frame ->
        process_buffered_frame(state, rest, actions, buffered_frame)
    end
  end

  defp process_buffered_frame(state, rest, actions, frame) do
    length = frame |> elem(1) |> byte_size()

    case decode_client_frame(state, frame) do
      {:ok, message} ->
        process_frames(
          state,
          rest,
          [{:client_message, message}, :activity, {:rate_limit, length} | actions]
        )

      :ignore ->
        process_frames(state, rest, [:activity, {:rate_limit, length} | actions])

      {:error, reason} ->
        close(state, reason, Enum.reverse([:activity, {:rate_limit, length} | actions]))
    end
  end

  defp authenticate(state, {type, body}) do
    if type == Frame.type(:client_info) do
      authenticate_client_info(state, body)
    else
      {:error, {:unexpected_handshake_frame, type}}
    end
  end

  defp authenticate_client_info(state, body) do
    with {:ok, client_public_key, client_info} <-
           Handshake.decode_client_info(body, state.server_private_key),
         {:ok, server_info} <-
           Handshake.server_info_frame(
             state.server_private_key,
             client_public_key,
             state.server_info
           ) do
      can_mesh = MeshKey.trusted?(state.mesh_key, client_info.mesh_key)

      state = %{
        state
        | phase: :authenticated,
          client_public_key: client_public_key,
          client_info: client_info,
          can_mesh: can_mesh,
          decoder:
            Decoder.with_frame_policy(
              state.decoder,
              &authenticated_frame_policy(&1, &2, can_mesh)
            )
      }

      actions = [
        {:authenticated, client_public_key, client_info, can_mesh},
        {:send, server_info},
        {:cancel_timeout, :handshake},
        {:set_timeout, :keep_alive, state.keep_alive_interval}
      ]

      {:ok, state, actions}
    end
  end

  defp decode_client_frame(state, {type, body}) do
    case Body.decode_client(type, body) do
      {:ok, message} -> authorize_client_message(state, message)
      other -> other
    end
  end

  defp authorize_client_message(%{can_mesh: false}, message)
       when elem(message, 0) in [:forward_packet, :close_peer],
       do: {:error, :insufficient_permissions}

  defp authorize_client_message(%{can_mesh: false}, :watch_connections),
    do: {:error, :insufficient_permissions}

  defp authorize_client_message(_state, message), do: {:ok, message}

  defp handshake_frame_policy(type, length) do
    cond do
      type == Frame.type(:client_info) and length > @max_client_info_length ->
        {:error, {:frame_too_large, length, @max_client_info_length}}

      type == Frame.type(:client_info) ->
        :buffer

      true ->
        authenticated_frame_policy(type, length, :pending)
    end
  end

  defp authenticated_frame_policy(type, length, mesh_permission) do
    case Frame.type_name(type) do
      {:ok, :send_packet} ->
        bounded(length, 32 + 65_536)

      {:ok, :ping} ->
        bounded(length, 1_000)

      {:ok, :note_preferred} ->
        exact(length, 1, :note_preferred_wrong_size)

      {:ok, :forward_packet} when mesh_permission in [true, :pending] ->
        bounded(length, 64 + 65_536)

      {:ok, :watch_connections} when mesh_permission in [true, :pending] ->
        exact(length, 0, :watch_connections_wrong_size)

      {:ok, :close_peer} when mesh_permission in [true, :pending] ->
        exact(length, 32, :close_peer_wrong_size)

      {:ok, name} when name in [:forward_packet, :watch_connections, :close_peer] ->
        {:error, :insufficient_permissions}

      _unknown_or_server_frame ->
        :discard
    end
  end

  defp bounded(length, maximum) when length <= maximum, do: :buffer
  defp bounded(length, maximum), do: {:error, {:frame_too_large, length, maximum}}

  defp exact(length, length, _reason), do: :buffer
  defp exact(_actual, _expected, reason), do: {:error, reason}

  defp close(state, reason, actions) do
    state = %{state | phase: :closed, close_reason: reason}
    {:close, state, reason, actions}
  end

  defp keep_alive_jitter(options) do
    case Keyword.get(options, :keep_alive_jitter) do
      nil -> :rand.uniform(5_000) - 1
      jitter when jitter in 0..4_999 -> jitter
    end
  end
end
