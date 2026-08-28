# Portions of this file describe behavior from Tailscale's DERP implementation.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Frame do
  @moduledoc """
  Binary framing for the DERP wire protocol.

  A frame starts with its one-byte type and an unsigned, big-endian 32-bit
  payload length. Decoding leaves the payload and any following frames in the
  returned remainder so transports can apply frame-specific limits before
  copying or decoding a body.

  Unknown type bytes are intentionally preserved. Whether to ignore or reject
  an unknown frame is a connection-state decision, not a codec decision.
  """

  @header_length 5
  @key_length 32
  @nonce_length 24
  @max_packet_size 64 * 1_024
  @max_info_length 1 * 1_024 * 1_024
  @max_write_length 10 * 1_024 * 1_024
  @magic "DERP🔑"

  @types [
    server_key: 0x01,
    client_info: 0x02,
    server_info: 0x03,
    send_packet: 0x04,
    recv_packet: 0x05,
    keep_alive: 0x06,
    note_preferred: 0x07,
    peer_gone: 0x08,
    peer_present: 0x09,
    forward_packet: 0x0A,
    watch_connections: 0x10,
    close_peer: 0x11,
    ping: 0x12,
    pong: 0x13,
    health: 0x14,
    restarting: 0x15
  ]

  @type type_code :: 0..255
  @type type_name ::
          :server_key
          | :client_info
          | :server_info
          | :send_packet
          | :forward_packet
          | :recv_packet
          | :keep_alive
          | :note_preferred
          | :peer_gone
          | :peer_present
          | :watch_connections
          | :close_peer
          | :ping
          | :pong
          | :health
          | :restarting

  @doc "The DERP protocol magic sent at the start of a server-key frame."
  @spec magic() :: binary()
  def magic, do: @magic

  @doc "The encoded frame-header size."
  @spec header_length() :: 5
  def header_length, do: @header_length

  @doc "The Curve25519 public-key size used by DERP addresses."
  @spec key_length() :: 32
  def key_length, do: @key_length

  @doc "The NaCl box nonce size."
  @spec nonce_length() :: 24
  def nonce_length, do: @nonce_length

  @doc "The maximum packet payload exposed to the overlay."
  @spec max_packet_size() :: 65_536
  def max_packet_size, do: @max_packet_size

  @doc "The maximum encrypted client/server information payload."
  @spec max_info_length() :: 1_048_576
  def max_info_length, do: @max_info_length

  @doc "Returns the byte assigned to a known DERP frame name."
  @spec type(type_name()) :: type_code()
  for {name, code} <- @types do
    def type(unquote(name)), do: unquote(code)
  end

  @doc "Returns the known name for a frame byte, preserving extensions as unknown."
  @spec type_name(type_code()) :: {:ok, type_name()} | :unknown
  for {name, code} <- @types do
    def type_name(unquote(code)), do: {:ok, unquote(name)}
  end

  def type_name(code) when code in 0..255, do: :unknown

  @doc "Encodes a frame header. Known atoms or any one-byte extension type are accepted."
  @spec encode_header(type_name() | type_code(), non_neg_integer()) :: binary()
  def encode_header(type, payload_length)
      when is_integer(type) and type in 0..255 and payload_length in 0..0xFFFFFFFF do
    <<type, payload_length::unsigned-big-32>>
  end

  def encode_header(type, payload_length) when is_atom(type) do
    encode_header(type(type), payload_length)
  end

  @doc """
  Decodes one header from a binary.

  Returns the untouched remainder on success, or the number of additional
  bytes needed when the input does not yet contain a complete header.
  """
  @spec decode_header(binary()) ::
          {:ok, type_code(), non_neg_integer(), binary()} | {:more, 1..5}
  def decode_header(<<type, payload_length::unsigned-big-32, rest::binary>>) do
    {:ok, type, payload_length, rest}
  end

  def decode_header(binary) when is_binary(binary) and byte_size(binary) < @header_length do
    {:more, @header_length - byte_size(binary)}
  end

  @doc "Encodes a complete frame as iodata without copying its payload."
  @spec encode(type_name() | type_code(), iodata()) :: iodata()
  def encode(type, payload) do
    payload_length = IO.iodata_length(payload)

    if payload_length > @max_write_length do
      raise ArgumentError, "unreasonably large frame write"
    end

    [encode_header(type, payload_length), payload]
  end
end
