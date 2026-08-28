// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command admission_smoke checks disallowed app-name admission and trusted
// mesh bypass with the official DERP HTTP client.
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
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: admission_smoke DERP_URL MESH_KEY")
		os.Exit(2)
	}

	meshKey, err := key.ParseDERPMesh(os.Args[2])
	must(err)

	bad := newClient(os.Args[1], "badapp", key.DERPMesh{})
	connect(bad)
	if message, err := bad.Recv(); err == nil {
		fail("disallowed client received %T instead of rejection", message)
	}
	bad.Close()

	good := newClient(os.Args[1], "goodapp", key.DERPMesh{})
	connect(good)
	requireServerInfo(good)
	good.Close()

	trusted := newClient(os.Args[1], "badapp", meshKey)
	connect(trusted)
	requireServerInfo(trusted)
	trusted.Close()

	fmt.Println("official Go clients observed disallowed app rejection and trusted mesh bypass")
}

func newClient(url, appName string, meshKey key.DERPMesh) *derphttp.Client {
	client, err := derphttp.NewClient(
		key.NewNode(),
		url,
		func(string, ...any) {},
		netmon.NewStatic(),
	)
	must(err)
	client.AppName = appName
	client.MeshKey = meshKey
	return client
}

func connect(client *derphttp.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(client.Connect(ctx))
}

func requireServerInfo(client *derphttp.Client) {
	message, err := client.Recv()
	must(err)
	if _, ok := message.(derp.ServerInfoMessage); !ok {
		fail("first message was %T, want ServerInfoMessage", message)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
