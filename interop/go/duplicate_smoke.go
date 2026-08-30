// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command duplicate_smoke proves the pinned server's default last-writer-active
// duplicate-key behavior using only unchanged official DERP HTTP clients.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
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

func recv(client *derphttp.Client) any {
	type result struct {
		message any
		err     error
	}
	received := make(chan result, 1)
	go func() {
		message, err := client.Recv()
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

func expectPacket(client *derphttp.Client, source key.NodePublic, payload []byte) {
	message := recv(client)
	packet, ok := message.(derp.ReceivedPacket)
	if !ok {
		panic(fmt.Sprintf("received %T, want derp.ReceivedPacket", message))
	}
	if packet.Source != source || !bytes.Equal(packet.Data, payload) {
		panic("packet source or payload mismatch")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: duplicate_smoke DERP_URL")
		os.Exit(2)
	}

	duplicateKey := key.NewNode()
	first := connect(os.Args[1], duplicateKey)
	defer first.Close()
	second := connect(os.Args[1], duplicateKey)
	defer second.Close()
	sender := connect(os.Args[1], key.NewNode())
	defer sender.Close()

	toNewest := []byte("newest duplicate")
	if err := sender.Send(duplicateKey.Public(), toNewest); err != nil {
		panic(err)
	}
	expectPacket(second, sender.SelfPublicKey(), toNewest)

	activity := []byte("first duplicate is active again")
	if err := first.Send(sender.SelfPublicKey(), activity); err != nil {
		panic(err)
	}
	expectPacket(sender, duplicateKey.Public(), activity)

	toActive := []byte("last writer receives")
	if err := sender.Send(duplicateKey.Public(), toActive); err != nil {
		panic(err)
	}
	expectPacket(first, sender.SelfPublicKey(), toActive)

	fmt.Println("official Go clients observed last-writer-active duplicate routing")
}
