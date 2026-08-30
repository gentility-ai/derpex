// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command pinned_cert_smoke verifies an unchanged official region client can
// dial DERPEX by raw IP using the DERP-map sha256-raw certificate pin.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: pinned_cert_smoke DERP_PORT CERT_PIN")
		os.Exit(2)
	}

	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}

	region := &tailcfg.DERPRegion{
		RegionID: 900,
		Nodes: []*tailcfg.DERPNode{{
			Name:     "custom",
			RegionID: 900,
			HostName: "127.0.0.1",
			CertName: os.Args[2],
			DERPPort: port,
		}},
	}

	client := derphttp.NewRegionClient(key.NewNode(), func(string, ...any) {}, netmon.NewStatic(), func() *tailcfg.DERPRegion {
		return region
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, connection, _, err := client.DialRegionTLS(ctx, region)
	if err != nil {
		panic(err)
	}
	defer connection.Close()

	fmt.Println("official Go region client accepted DERPEX raw-IP certificate pin")
}
