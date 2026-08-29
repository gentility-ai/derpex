defmodule Derpex.Connection do
  @moduledoc """
  Pure protocol state machine for one DERP connection.

  Socket adapters execute returned actions in order, and the order is Go's: a
  client is admitted, registered for routing, sent its server info, and only
  then does its send loop start. Registering first means a packet sent to the
  new client during its handshake is queued rather than dropped as unknown;
  starting the send loop last means no queued packet can overtake the server
  info. No action sends packet data through a process mailbox; packet messages
  are consumed synchronously by the reader.
  """

  alias Derpex.ClientInfo
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Frame.Decoder
  alias Derpex.Handshake
  alias Derpex.MeshKey
  alias Derpex.Secret
  alias Derpex.ServerInfo

  @handshake_timeout 10_000

  # The pinned Go server accepts a client-info frame up to 256 KiB
  # (`recvClientKey`). Real ClientInfo is under 200 bytes, so DERPEX caps the
  # pre-authentication frame at 16 KiB. Recorded as a compatibility exception
  # in PLAN.md Section 2.3.
  @max_client_info_length 16 * 1_024

  # Go's `recvClientKey` rejects `fl < derp.KeyLen + derp.NonceLen` as "short
  # client info" before reading the body.
  @min_client_info_length Frame.key_length() + Frame.nonce_length()

  @derive {Inspect, except: [:private_key, :mesh_key]}
  defstruct [
    :private_key,
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
          | {:register, binary(), ClientInfo.t(), boolean()}
          | :start_send_loop
          | {:rate_limit, non_neg_integer()}
          | :activity
          | {:server_message, Body.server_message()}
          | {:client_message, Body.client_message()}

  @opaque t :: %__MODULE__{
            private_key: Secret.t(),
            server_info: ServerInfo.t(),
            decoder: Decoder.t(),
            phase: phase(),
            client_public_key: nil | binary(),
            client_info: nil | ClientInfo.t(),
            mesh_key: nil | Secret.t(),
            can_mesh: boolean(),
            keep_alive_interval: pos_integer(),
            close_reason: nil | term()
          }

  @doc """
  Creates a connection and returns its greeting and handshake deadline actions.

  Both `private_key` and the `:mesh_key` option are `Derpex.Secret` references,
  wrapped once by the caller that read them from configuration or disk.
  """
  @spec new(Secret.t(), keyword()) :: {:ok, t(), [action()]} | {:error, atom()}
  def new(private_key, options \\ []) do
    server_info =
      Keyword.get(options, :server_info, %ServerInfo{version: Handshake.protocol_version()})

    with {:ok, greeting} <- Handshake.server_key_frame(Secret.reveal(private_key)) do
      state = %__MODULE__{
        private_key: private_key,
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
    private_key = Secret.reveal(state.private_key)

    with {:ok, client_public_key, client_info} <-
           Handshake.decode_client_info(body, private_key),
         {:ok, server_info} <-
           Handshake.server_info_frame(
             private_key,
             client_public_key,
             state.server_info
           ) do
      can_mesh = MeshKey.trusted?(Secret.reveal(state.mesh_key), client_info.mesh_key)

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
        {:register, client_public_key, client_info, can_mesh},
        {:send, server_info},
        :start_send_loop,
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

  # Go's `recvClientKey` rejects a first frame whose header type is not
  # `client_info`, so the body of such a frame is never read. Once the
  # client-info header is admitted, later headers pipelined into the same chunk
  # are governed by the authenticated policy with mesh permission still pending.
  defp handshake_frame_policy(type, length) do
    cond do
      type != Frame.type(:client_info) ->
        {:error, {:unexpected_handshake_frame, type}}

      length > @max_client_info_length ->
        {:error, {:frame_too_large, length, @max_client_info_length}}

      length < @min_client_info_length ->
        {:error, {:frame_too_small, length, @min_client_info_length}}

      true ->
        {:buffer, &pending_frame_policy/2}
    end
  end

  defp pending_frame_policy(type, length),
    do: authenticated_frame_policy(type, length, :pending)

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
