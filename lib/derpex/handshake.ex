# This module implements behavior from Tailscale's DERP handshake.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Handshake do
  @moduledoc """
  Stateless DERP handshake frame construction and authentication.

  The server's private key is passed explicitly so connection processes never
  own or duplicate key-management state. Transport ordering belongs to the
  connection state machine; this module owns only wire and crypto compatibility.
  """

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.ServerInfo

  @protocol_version 2
  @key_length 32
  @nonce_length 24
  @max_server_key_length 1_024
  @max_client_info_length 256 * 1_024
  @max_server_info_length @nonce_length + 1 * 1_024 * 1_024

  @doc "The current wire-incompatible DERP protocol version."
  @spec protocol_version() :: 2
  def protocol_version, do: @protocol_version

  @doc "Builds the initial server-key frame."
  @spec server_key_frame(binary()) :: {:ok, iodata()} | {:error, atom()}
  def server_key_frame(server_private_key) do
    with {:ok, server_public_key} <- Crypto.public_key(server_private_key) do
      {:ok, Frame.encode(:server_key, [Frame.magic(), server_public_key])}
    end
  end

  @doc "Validates a server-key body while accepting bounded future extensions."
  @spec decode_server_key(binary()) :: {:ok, binary()} | {:error, atom()}
  def decode_server_key(payload) when byte_size(payload) > @max_server_key_length,
    do: {:error, :server_greeting_too_large}

  def decode_server_key(
        <<magic::binary-size(8), server_public_key::binary-size(@key_length),
          _extensions::binary>>
      ) do
    if magic == Frame.magic(),
      do: {:ok, server_public_key},
      else: {:error, :invalid_server_greeting}
  end

  def decode_server_key(_payload), do: {:error, :invalid_server_greeting}

  @doc "Builds a client's authenticated ClientInfo frame."
  @spec client_info_frame(binary(), binary(), ClientInfo.t()) ::
          {:ok, iodata()} | {:error, atom()}
  def client_info_frame(client_private_key, server_public_key, %ClientInfo{} = info) do
    with true <- ClientInfo.valid_app_name?(info.app_name),
         {:ok, client_public_key} <- Crypto.public_key(client_private_key),
         {:ok, msgbox} <-
           Crypto.seal_to(client_private_key, server_public_key, ClientInfo.encode(info)) do
      {:ok, Frame.encode(:client_info, [client_public_key, msgbox])}
    else
      false -> {:error, :invalid_app_name}
      {:error, _reason} = error -> error
    end
  end

  @doc "Authenticates and decodes a client-info body before registration."
  @spec decode_client_info(binary(), binary()) ::
          {:ok, binary(), ClientInfo.t()} | {:error, term()}
  def decode_client_info(payload, _server_private_key)
      when byte_size(payload) < @key_length + @nonce_length,
      do: {:error, :short_client_info}

  def decode_client_info(payload, _server_private_key)
      when byte_size(payload) > @max_client_info_length,
      do: {:error, :long_client_info}

  def decode_client_info(
        <<client_public_key::binary-size(@key_length), msgbox::binary>>,
        server_private_key
      ) do
    with {:ok, json} <- Crypto.open_from(server_private_key, client_public_key, msgbox),
         {:ok, info} <- ClientInfo.decode(json) do
      {:ok, client_public_key, info}
    else
      {:error, :authentication_failed} -> {:error, :cannot_open_client_info}
      {:error, reason} -> {:error, {:invalid_client_info, reason}}
    end
  end

  @doc "Builds the authenticated ServerInfo frame sent after client registration."
  @spec server_info_frame(binary(), binary(), ServerInfo.t()) ::
          {:ok, iodata()} | {:error, atom()}
  def server_info_frame(server_private_key, client_public_key, %ServerInfo{} = info) do
    with {:ok, msgbox} <-
           Crypto.seal_to(server_private_key, client_public_key, ServerInfo.encode(info)) do
      {:ok, Frame.encode(:server_info, msgbox)}
    end
  end

  @doc "Authenticates and decodes a server-info body."
  @spec decode_server_info(binary(), binary(), binary()) ::
          {:ok, ServerInfo.t()} | {:error, term()}
  def decode_server_info(payload, _client_private_key, _server_public_key)
      when byte_size(payload) < @nonce_length,
      do: {:error, :short_server_info}

  def decode_server_info(payload, _client_private_key, _server_public_key)
      when byte_size(payload) > @max_server_info_length,
      do: {:error, :long_server_info}

  def decode_server_info(payload, client_private_key, server_public_key) do
    with {:ok, json} <- Crypto.open_from(client_private_key, server_public_key, payload),
         {:ok, info} <- ServerInfo.decode(json) do
      {:ok, info}
    else
      {:error, :authentication_failed} -> {:error, :cannot_open_server_info}
      {:error, reason} -> {:error, {:invalid_server_info, reason}}
    end
  end
end
