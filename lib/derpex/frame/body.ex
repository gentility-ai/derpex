# This module implements behavior from Tailscale's DERP frame handlers.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Frame.Body do
  @moduledoc """
  Frame-body validation and encoding at the client/server trust boundary.

  A malformed frame that closes a server connection is returned as an error.
  A short server extension that the Go client skips while continuing to read is
  returned as `{:drop, reason}`. Unknown types are returned as `:ignore`.
  """

  alias Derpex.ClientInfo
  alias Derpex.Frame

  @key_length 32
  @max_packet_size 65_536

  @type client_message ::
          {:note_preferred, boolean()}
          | {:send_packet, binary(), binary()}
          | {:forward_packet, binary(), binary(), binary()}
          | :watch_connections
          | {:close_peer, binary()}
          | {:ping, <<_::64>>}
          | {:pong, <<_::64>>}

  @type server_message ::
          :keep_alive
          | {:peer_gone, binary(), 0..255}
          | {:peer_present, binary(), nil | binary(), nil | non_neg_integer(), 0..255, binary()}
          | {:recv_packet, binary(), binary()}
          | {:ping, <<_::64>>}
          | {:pong, <<_::64>>}
          | {:health, binary()}
          | {:restarting, non_neg_integer(), non_neg_integer()}

  @doc "Parses a frame sent from a client to a DERP server."
  @spec decode_client(Frame.type_code(), binary()) ::
          {:ok, client_message()} | {:error, atom()} | :ignore
  def decode_client(type, payload) when is_integer(type) and is_binary(payload) do
    case Frame.type_name(type) do
      {:ok, :note_preferred} -> decode_note_preferred(payload)
      {:ok, :send_packet} -> decode_send_packet(payload)
      {:ok, :forward_packet} -> decode_forward_packet(payload)
      {:ok, :watch_connections} -> decode_watch_connections(payload)
      {:ok, :close_peer} -> decode_close_peer(payload)
      {:ok, :ping} -> decode_client_ping(payload)
      _other -> :ignore
    end
  end

  @doc "Parses a frame sent from a DERP server to a client."
  @spec decode_server(Frame.type_code(), binary()) ::
          {:ok, server_message()} | {:drop, atom()} | :ignore
  def decode_server(type, payload) when is_integer(type) and is_binary(payload) do
    case Frame.type_name(type) do
      {:ok, name} -> decode_known_server(name, payload)
      :unknown -> :ignore
    end
  end

  @doc "Encodes a client-originated semantic message as a complete DERP frame."
  @spec encode_client(client_message()) :: {:ok, iodata()} | {:error, atom()}
  def encode_client({:note_preferred, preferred}) when is_boolean(preferred) do
    {:ok, Frame.encode(:note_preferred, <<if(preferred, do: 1, else: 0)>>)}
  end

  def encode_client({:send_packet, <<destination::binary-size(32)>>, packet})
      when is_binary(packet) and byte_size(packet) <= @max_packet_size do
    {:ok, Frame.encode(:send_packet, [destination, packet])}
  end

  def encode_client(
        {:forward_packet, <<source::binary-size(32)>>, <<destination::binary-size(32)>>, packet}
      )
      when is_binary(packet) and byte_size(packet) <= @max_packet_size do
    {:ok, Frame.encode(:forward_packet, [source, destination, packet])}
  end

  def encode_client(:watch_connections), do: {:ok, Frame.encode(:watch_connections, "")}

  def encode_client({:close_peer, <<key::binary-size(32)>>}) do
    {:ok, Frame.encode(:close_peer, key)}
  end

  def encode_client({:ping, <<ping::binary-size(8)>>}),
    do: {:ok, Frame.encode(:ping, ping)}

  def encode_client({:pong, <<pong::binary-size(8)>>}),
    do: {:ok, Frame.encode(:pong, pong)}

  def encode_client(_message), do: {:error, :invalid_message}

  @doc "Encodes a server-originated semantic message as a complete DERP frame."
  @spec encode_server(server_message()) :: {:ok, iodata()} | {:error, atom()}
  def encode_server(:keep_alive), do: {:ok, Frame.encode(:keep_alive, "")}

  def encode_server({:peer_gone, <<key::binary-size(32)>>, reason}) when reason in 0..255 do
    {:ok, Frame.encode(:peer_gone, [key, <<reason>>])}
  end

  def encode_server(
        {:peer_present, <<key::binary-size(32)>>, <<ip::binary-size(16)>>, port, flags, app_name}
      )
      when port in 0..65_535 and flags in 0..255 and is_binary(app_name) and
             byte_size(app_name) <= 255 do
    if ClientInfo.valid_app_name?(app_name) do
      payload = [key, ip, <<port::unsigned-big-16, flags, byte_size(app_name)>>, app_name]
      {:ok, Frame.encode(:peer_present, payload)}
    else
      {:error, :invalid_app_name}
    end
  end

  def encode_server({:recv_packet, <<source::binary-size(32)>>, packet})
      when is_binary(packet) and byte_size(packet) <= @max_packet_size do
    {:ok, Frame.encode(:recv_packet, [source, packet])}
  end

  def encode_server({:ping, <<ping::binary-size(8)>>}), do: {:ok, Frame.encode(:ping, ping)}
  def encode_server({:pong, <<pong::binary-size(8)>>}), do: {:ok, Frame.encode(:pong, pong)}

  def encode_server({:health, problem}) when is_binary(problem),
    do: {:ok, Frame.encode(:health, problem)}

  def encode_server({:restarting, reconnect_ms, try_for_ms})
      when reconnect_ms in 0..0xFFFFFFFF and try_for_ms in 0..0xFFFFFFFF do
    {:ok,
     Frame.encode(:restarting, <<reconnect_ms::unsigned-big-32, try_for_ms::unsigned-big-32>>)}
  end

  def encode_server(_message), do: {:error, :invalid_message}

  defp decode_note_preferred(<<preferred>>), do: {:ok, {:note_preferred, preferred != 0}}
  defp decode_note_preferred(_payload), do: {:error, :note_preferred_wrong_size}

  defp decode_known_server(:keep_alive, _payload), do: {:ok, :keep_alive}
  defp decode_known_server(:peer_gone, payload), do: decode_peer_gone(payload)
  defp decode_known_server(:peer_present, payload), do: decode_peer_present(payload)
  defp decode_known_server(:recv_packet, payload), do: decode_recv_packet(payload)
  defp decode_known_server(:ping, payload), do: decode_server_ping(payload)
  defp decode_known_server(:pong, payload), do: decode_server_pong(payload)
  defp decode_known_server(:health, payload), do: {:ok, {:health, payload}}
  defp decode_known_server(:restarting, payload), do: decode_restarting(payload)
  defp decode_known_server(_name, _payload), do: :ignore

  defp decode_send_packet(<<destination::binary-size(@key_length), packet::binary>>)
       when byte_size(packet) <= @max_packet_size do
    {:ok, {:send_packet, destination, packet}}
  end

  defp decode_send_packet(payload) when byte_size(payload) < @key_length,
    do: {:error, :short_send_packet}

  defp decode_send_packet(_payload), do: {:error, :packet_too_large}

  defp decode_forward_packet(
         <<source::binary-size(@key_length), destination::binary-size(@key_length),
           packet::binary>>
       )
       when byte_size(packet) <= @max_packet_size do
    {:ok, {:forward_packet, source, destination, packet}}
  end

  defp decode_forward_packet(payload) when byte_size(payload) < @key_length * 2,
    do: {:error, :short_forward_packet}

  defp decode_forward_packet(_payload), do: {:error, :packet_too_large}

  defp decode_watch_connections(""), do: {:ok, :watch_connections}
  defp decode_watch_connections(_payload), do: {:error, :watch_connections_wrong_size}

  defp decode_close_peer(<<key::binary-size(@key_length)>>), do: {:ok, {:close_peer, key}}
  defp decode_close_peer(_payload), do: {:error, :close_peer_wrong_size}

  defp decode_client_ping(<<ping::binary-size(8), _extensions::binary>> = payload)
       when byte_size(payload) <= 1_000 do
    {:ok, {:ping, ping}}
  end

  defp decode_client_ping(payload) when byte_size(payload) < 8, do: {:error, :short_ping}
  defp decode_client_ping(_payload), do: {:error, :ping_too_large}

  defp decode_peer_gone(<<key::binary-size(@key_length)>>),
    do: {:ok, {:peer_gone, key, 0x00}}

  defp decode_peer_gone(<<key::binary-size(@key_length), reason, _extensions::binary>>),
    do: {:ok, {:peer_gone, key, reason}}

  defp decode_peer_gone(_payload), do: {:drop, :short_peer_gone}

  defp decode_peer_present(<<key::binary-size(@key_length), rest::binary>>) do
    decode_peer_present_address(key, rest)
  end

  defp decode_peer_present(_payload), do: {:drop, :short_peer_present}

  defp decode_peer_present_address(
         key,
         <<ip::binary-size(16), port::unsigned-big-16, rest::binary>>
       ) do
    decode_peer_present_flags(key, ip, port, rest)
  end

  defp decode_peer_present_address(key, _rest),
    do: {:ok, {:peer_present, key, nil, nil, 0, ""}}

  defp decode_peer_present_flags(key, ip, port, <<flags, rest::binary>>) do
    decode_peer_present_name(key, ip, port, flags, rest)
  end

  defp decode_peer_present_flags(key, ip, port, ""),
    do: {:ok, {:peer_present, key, ip, port, 0, ""}}

  defp decode_peer_present_name(key, ip, port, flags, <<name_length, rest::binary>>)
       when byte_size(rest) >= name_length do
    <<app_name::binary-size(^name_length), _extensions::binary>> = rest
    app_name = if ClientInfo.valid_app_name?(app_name), do: app_name, else: ""
    {:ok, {:peer_present, key, ip, port, flags, app_name}}
  end

  defp decode_peer_present_name(key, ip, port, flags, _rest),
    do: {:ok, {:peer_present, key, ip, port, flags, ""}}

  defp decode_recv_packet(<<source::binary-size(@key_length), packet::binary>>),
    do: {:ok, {:recv_packet, source, packet}}

  defp decode_recv_packet(_payload), do: {:drop, :short_recv_packet}

  defp decode_server_ping(<<ping::binary-size(8), _extensions::binary>>),
    do: {:ok, {:ping, ping}}

  defp decode_server_ping(_payload), do: {:drop, :short_ping}

  defp decode_server_pong(<<pong::binary-size(8), _extensions::binary>>),
    do: {:ok, {:pong, pong}}

  defp decode_server_pong(_payload), do: {:drop, :short_pong}

  defp decode_restarting(
         <<reconnect_ms::unsigned-big-32, try_for_ms::unsigned-big-32, _extensions::binary>>
       ) do
    {:ok, {:restarting, reconnect_ms, try_for_ms}}
  end

  defp decode_restarting(_payload), do: {:drop, :short_restarting}
end
