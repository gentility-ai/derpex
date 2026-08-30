// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command relay_smoke uses two unchanged official Go DERP HTTP clients to
// prove authenticated packet relay through a running DERPEX listener.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func connect(url string, private key.NodePrivate) *derphttp.Client {
	client, err := derphttp.NewClient(private, url, func(string, ...any) {}, netmon.NewStatic())
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		panic(err)
	}
	message, err := client.Recv()
	if err != nil {
		panic(err)
	}
	if _, ok := message.(derp.ServerInfoMessage); !ok {
		panic(fmt.Sprintf("first DERP message was %T", message))
	}
	return client
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: relay_smoke DERP_URL")
		os.Exit(2)
	}

	firstKey := key.NewNode()
	secondKey := key.NewNode()
	first := connect(os.Args[1], firstKey)
	defer first.Close()
	second := connect(os.Args[1], secondKey)
	defer second.Close()

	type result struct {
		message any
		err     error
	}
	recv := func() any {
		received := make(chan result, 1)
		go func() {
			message, err := second.Recv()
			received <- result{message: message, err: err}
		}()

		select {
		case result := <-received:
			if result.err != nil {
				panic(result.err)
			}
			return result.message
		case <-time.After(10 * time.Second):
			panic("timed out waiting for DERP message")
		}
	}

	payloads := [][]byte{
		{},
		[]byte("official Go clients relayed through DERPEX"),
		bytes.Repeat([]byte{0xa5}, derp.MaxPacketSize),
	}
	for _, payload := range payloads {
		if err := first.Send(second.SelfPublicKey(), payload); err != nil {
			panic(err)
		}
		message := recv()
		packet, ok := message.(derp.ReceivedPacket)
		if !ok {
			panic(fmt.Sprintf("received %T, want derp.ReceivedPacket", message))
		}
		if packet.Source != first.SelfPublicKey() || !bytes.Equal(packet.Data, payload) {
			panic("relayed packet source or payload mismatch")
		}
	}

	firstPublic := first.SelfPublicKey()
	if err := first.Close(); err != nil {
		panic(err)
	}
	message := recv()
	peerGone, ok := message.(derp.PeerGoneMessage)
	if !ok {
		panic(fmt.Sprintf("received %T, want derp.PeerGoneMessage", message))
	}
	if peerGone.Peer != firstPublic || peerGone.Reason != derp.PeerGoneReasonDisconnected {
		panic("peer-gone key or reason mismatch")
	}

	unknownKey := key.NewNode().Public()
	discoPacket := unknownKey.AppendTo([]byte(disco.Magic))
	discoPacket = append(discoPacket, make([]byte, disco.NonceLen)...)
	if err := second.Send(unknownKey, discoPacket); err != nil {
		panic(err)
	}
	message = recv()
	peerGone, ok = message.(derp.PeerGoneMessage)
	if !ok {
		panic(fmt.Sprintf("received %T, want derp.PeerGoneMessage", message))
	}
	if peerGone.Peer != unknownKey || peerGone.Reason != derp.PeerGoneReasonNotHere {
		panic("unknown-destination peer-gone key or reason mismatch")
	}

	fmt.Println("official Go clients relayed packet boundaries and observed both peer-gone reasons")
}
