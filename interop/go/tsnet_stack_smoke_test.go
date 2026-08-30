// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// This test is compiled against the pinned, unchanged Tailscale checkout. It
// exercises DERPEX through tsnet's real LocalBackend, magicsock, WireGuard, and
// derphttp client stack rather than through a DERP protocol client in isolation.
package derpexinterop

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
)

const derpexRegionID tailcfg.DERPRegionID = 900

func TestDERPEXTsnetStack(t *testing.T) {
	port, err := strconv.Atoi(requiredEnv(t, "DERPEX_INTEROP_PORT"))
	if err != nil {
		t.Fatalf("parse DERPEX_INTEROP_PORT: %v", err)
	}
	certPin := requiredEnv(t, "DERPEX_INTEROP_CERT_PIN")

	// Corp network namespaces are useful in Tailscale's integration harness,
	// but this host-network smoke deliberately talks to DERPEX on loopback.
	netns.SetEnabled(false)
	defer netns.SetEnabled(true)

	derpMap := &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			derpexRegionID: {
				RegionID:   derpexRegionID,
				RegionCode: "dxp",
				RegionName: "DERPEX integration",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "900a",
						RegionID: derpexRegionID,
						HostName: "127.0.0.1",
						CertName: certPin,
						IPv4:     "127.0.0.1",
						IPv6:     "none",
						STUNPort: -1,
						DERPPort: port,
					},
				},
			},
		},
	}

	control := &testcontrol.Server{
		DERPMap:          derpMap,
		AllNodesSameUser: true,
		AllOnline:        true,
		Logf:             logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	defer control.HTTPTestServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	node1, ip1 := startNode(t, ctx, control.HTTPTestServer.URL, "derpex-node-1")
	defer node1.Close()
	node2, _ := startNode(t, ctx, control.HTTPTestServer.URL, "derpex-node-2")
	defer node2.Close()

	waitForHomeDERP(t, ctx, node1)
	waitForHomeDERP(t, ctx, node2)

	client2, err := node2.LocalClient()
	if err != nil {
		t.Fatalf("node 2 LocalClient: %v", err)
	}

	sentBefore := clientMetricValue(t, "magicsock_send_data_derp")
	receivedBefore := clientMetricValue(t, "magicsock_recv_data_derp")
	var lastResult string
	for {
		pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
		result, pingErr := client2.Ping(pingCtx, ip1, tailcfg.PingICMP)
		cancelPing()

		if pingErr == nil && result != nil && result.Err == "" {
			break
		}
		lastResult = fmt.Sprintf("result=%+v error=%v", result, pingErr)

		select {
		case <-ctx.Done():
			t.Fatalf("tunnel ping did not use DERPEX: %s; %v", lastResult, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}

	for {
		sentAfter := clientMetricValue(t, "magicsock_send_data_derp")
		receivedAfter := clientMetricValue(t, "magicsock_recv_data_derp")
		if sentAfter > sentBefore && receivedAfter > receivedBefore {
			fmt.Println("official tsnet nodes relayed an encrypted tunnel ping through DERPEX")
			return
		}

		select {
		case <-ctx.Done():
			t.Fatalf(
				"tunnel ping did not increment DERP data counters: sent=%d->%d received=%d->%d; %v",
				sentBefore,
				sentAfter,
				receivedBefore,
				receivedAfter,
				ctx.Err(),
			)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func startNode(t *testing.T, ctx context.Context, controlURL, hostname string) (*tsnet.Server, netip.Addr) {
	t.Helper()

	node := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), hostname),
		ControlURL: controlURL,
		Hostname:   hostname,
		Ephemeral:  true,
		Logf:       logger.Discard,
		UserLogf:   logger.Discard,
	}
	status, err := node.Up(ctx)
	if err != nil {
		node.Close()
		t.Fatalf("start %s: %v", hostname, err)
	}
	if len(status.TailscaleIPs) == 0 {
		node.Close()
		t.Fatalf("start %s: control returned no Tailscale IPs", hostname)
	}
	return node, status.TailscaleIPs[0]
}

func waitForHomeDERP(t *testing.T, ctx context.Context, node *tsnet.Server) {
	t.Helper()

	magicConn := tsnet.TestHooks.LocalBackend(node).MagicConn()
	magicConn.ForceSetNearestDERP(derpexRegionID)
	health := node.Sys().HealthTracker.Get()

	for health.GetDERPRegionReceivedTime(derpexRegionID).IsZero() {
		select {
		case <-ctx.Done():
			t.Fatalf("wait for DERPEX home connection: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s must be set", name)
	}
	return value
}

func clientMetricValue(t *testing.T, name string) int64 {
	t.Helper()
	for _, metric := range clientmetric.Metrics() {
		if metric.Name() == name {
			return metric.Value()
		}
	}
	t.Fatalf("Tailscale client metric %q is unavailable", name)
	return 0
}
