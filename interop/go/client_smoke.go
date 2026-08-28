// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command client_smoke connects an unchanged official Go DERP HTTP client to a
// running DERPEX listener and requires the authenticated ServerInfo message.
// Run it from the pinned tailscale/tailscale module checkout.
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: client_smoke DERP_URL")
		os.Exit(2)
	}

	client, err := derphttp.NewClient(
		key.NewNode(),
		os.Args[1],
		func(string, ...any) {},
		netmon.NewStatic(),
	)
	if err != nil {
		panic(err)
	}
	defer client.Close()

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
		panic(fmt.Sprintf("first DERP message was %T, want derp.ServerInfoMessage", message))
	}

	recvErrors := make(chan error, 1)
	go func() {
		for {
			if _, err := client.Recv(); err != nil {
				recvErrors <- err
				return
			}
		}
	}()
	if err := client.Ping(ctx); err != nil {
		panic(err)
	}

	fmt.Printf("official Go client authenticated and pinged: client=%s server=%s\n", client.SelfPublicKey(), client.ServerPublicKey())
}
