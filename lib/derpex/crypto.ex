defmodule Derpex.Crypto do
  @moduledoc """
  Elixir boundary for the small DERPEX native cryptography implementation.

  Packet framing and relay traffic must never cross this boundary.
  """

  alias Derpex.Crypto.Native

  @key_length 32
  @nonce_length 24

  @doc "Returns true after the native library has loaded successfully."
  @spec loaded?() :: boolean()
  def loaded?, do: Native.loaded()

  @doc "Generates a Curve25519 keypair as `{public_key, private_key}`."
  @spec generate_keypair() :: {binary(), binary()}
  def generate_keypair do
    private_key = :crypto.strong_rand_bytes(@key_length)
    {:ok, public_key} = public_key(private_key)
    {public_key, private_key}
  end

  @doc "Derives the Curve25519 public key for a raw 32-byte private key."
  @spec public_key(binary()) :: {:ok, binary()} | {:error, atom()}
  defdelegate public_key(private_key), to: Native

  @doc "Seals plaintext to a peer and prefixes a fresh 24-byte nonce."
  @spec seal_to(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def seal_to(private_key, peer_public_key, plaintext) do
    seal_to(private_key, peer_public_key, :crypto.strong_rand_bytes(@nonce_length), plaintext)
  end

  @doc "Seals plaintext using an explicit nonce, primarily for compatibility vectors."
  @spec seal_to(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  defdelegate seal_to(private_key, peer_public_key, nonce, plaintext),
    to: Native,
    as: :seal

  @doc "Opens a nonce-prefixed NaCl box authenticated by the peer public key."
  @spec open_from(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  defdelegate open_from(private_key, peer_public_key, boxed), to: Native, as: :open
end
