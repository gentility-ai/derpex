defmodule Derpex.CryptoTest do
  use ExUnit.Case, async: true

  alias Derpex.Crypto

  @sender_private "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  @sender_public "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
  @receiver_private "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
  @receiver_public "87968c1c1642bd0600f6ad869b88f92c9623d0dfc44f01deffe21c9add3dca5f"
  @nonce "000102030405060708090a0b0c0d0e0f1011121314151617"
  @boxed "000102030405060708090a0b0c0d0e0f10111213141516172a916847b37c142f99359969f03558e5abddcdd6ebdef4b98ce5fd6d9e9af008c75f8d3f71c6be5997ddb640a7cdf1d3"
  @plaintext "DERPEX Go NaCl box compatibility"

  test "matches the deterministic Go x/crypto/nacl/box vector" do
    sender_private = hex(@sender_private)
    sender_public = hex(@sender_public)
    receiver_private = hex(@receiver_private)
    receiver_public = hex(@receiver_public)
    nonce = hex(@nonce)
    boxed = hex(@boxed)

    assert Crypto.public_key(sender_private) == {:ok, sender_public}
    assert Crypto.public_key(receiver_private) == {:ok, receiver_public}

    assert Crypto.seal_to(sender_private, receiver_public, nonce, @plaintext) == {:ok, boxed}
    assert Crypto.open_from(receiver_private, sender_public, boxed) == {:ok, @plaintext}
  end

  test "generates a usable keypair and nonce-prefixed box" do
    {alice_public, alice_private} = Crypto.generate_keypair()
    {bob_public, bob_private} = Crypto.generate_keypair()

    assert byte_size(alice_public) == 32
    assert byte_size(alice_private) == 32
    assert {:ok, boxed} = Crypto.seal_to(alice_private, bob_public, "hello")
    assert byte_size(boxed) == 24 + 16 + 5
    assert Crypto.open_from(bob_private, alice_public, boxed) == {:ok, "hello"}
  end

  test "rejects authentication failures without exposing plaintext" do
    sender_public = hex(@sender_public)
    receiver_private = hex(@receiver_private)
    boxed = hex(@boxed)
    prefix_size = byte_size(boxed) - 1
    <<prefix::binary-size(^prefix_size), last>> = boxed
    tampered = <<prefix::binary, rem(last + 1, 256)>>

    assert Crypto.open_from(receiver_private, sender_public, tampered) ==
             {:error, :authentication_failed}
  end

  test "validates key, nonce, and box lengths at the NIF boundary" do
    sender_private = hex(@sender_private)
    receiver_public = hex(@receiver_public)

    assert Crypto.public_key("short") == {:error, :bad_key_size}

    assert Crypto.seal_to(sender_private, receiver_public, "short", "hello") ==
             {:error, :bad_nonce_size}

    assert Crypto.open_from(sender_private, receiver_public, "short") ==
             {:error, :bad_nonce_size}
  end

  defp hex(value), do: Base.decode16!(value, case: :mixed)
end
