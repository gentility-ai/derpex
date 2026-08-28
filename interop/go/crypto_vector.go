// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command crypto_vector emits the deterministic NaCl box vector used by the
// Elixir/NIF compatibility test. Run it from the pinned Tailscale checkout so
// its golang.org/x/crypto dependency is resolved by the upstream module lock.
package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func mustHex(value string) []byte {
	b, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return b
}

func array32(value []byte) (out [32]byte) {
	copy(out[:], value)
	return out
}

func array24(value []byte) (out [24]byte) {
	copy(out[:], value)
	return out
}

func main() {
	senderPrivate := array32(mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	receiverPrivate := array32(mustHex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"))
	nonce := array24(mustHex("000102030405060708090a0b0c0d0e0f1011121314151617"))
	plaintext := []byte("DERPEX Go NaCl box compatibility")

	senderPublicBytes, err := curve25519.X25519(senderPrivate[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	receiverPublicBytes, err := curve25519.X25519(receiverPrivate[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	senderPublic := array32(senderPublicBytes)
	receiverPublic := array32(receiverPublicBytes)
	sealed := box.Seal(nonce[:], plaintext, &nonce, &receiverPublic, &senderPrivate)

	fmt.Printf("sender_public=%x\n", senderPublic)
	fmt.Printf("receiver_public=%x\n", receiverPublic)
	fmt.Printf("boxed=%x\n", sealed)
}
