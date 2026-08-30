// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command send_rate_smoke uses unchanged official Go DERP HTTP clients to
// verify DERPEX's encrypted ServerInfo configures client-side send limiting.
package main

import (
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

type result struct {
	message any
	err     error
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: send_rate_smoke DERP_URL")
		os.Exit(2)
	}

	sender := connect(os.Args[1], key.NewNode())
	defer sender.Close()
	receiver := connect(os.Args[1], key.NewNode())
	defer receiver.Close()

	received := make(chan result, 1000)
	go func() {
		for {
			message, err := receiver.Recv()
			received <- result{message: message, err: err}
			if err != nil {
				return
			}
		}
	}()

	payload := make([]byte, 1000)
	for range 1000 {
		if err := sender.Send(receiver.SelfPublicKey(), payload); err != nil {
			panic(err)
		}
	}

	count := 0
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case result := <-received:
			if result.err != nil {
				panic(result.err)
			}
			if _, ok := result.message.(derp.ReceivedPacket); ok {
				count++
			}
		case <-timer.C:
			if count < 2 || count >= 1000 {
				panic(fmt.Sprintf("received %d packets; want at least 2 and fewer than 1000", count))
			}
			fmt.Printf("official Go client obeyed DERPEX send limit (%d of 1000 packets sent)\n", count)
			return
		}
	}
}
