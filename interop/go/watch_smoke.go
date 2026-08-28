// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command watch_smoke uses the official DERP HTTP client to exercise trusted
// mesh connection snapshots and live presence updates.
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

type recvResult struct {
	message any
	err     error
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: watch_smoke DERP_URL MESH_KEY")
		os.Exit(2)
	}

	meshKey, err := key.ParseDERPMesh(os.Args[2])
	must(err)

	first := connect(os.Args[1], "test-app", key.DERPMesh{}, false)
	defer first.Close()

	watcher := connect(os.Args[1], "", meshKey, true)
	defer watcher.Close()

	wantSnapshot := map[key.NodePublic]bool{
		first.SelfPublicKey():   false,
		watcher.SelfPublicKey(): false,
	}
	for remaining(wantSnapshot) > 0 {
		present := requirePresent(recvTimeout(watcher))
		if _, ok := wantSnapshot[present.Key]; !ok {
			fail("snapshot contained unexpected peer %v", present.Key)
		}
		if present.Key == first.SelfPublicKey() {
			if present.AppName != "test-app" {
				fail("regular client app name = %q, want test-app", present.AppName)
			}
			if present.Flags&derp.PeerPresentIsRegular == 0 {
				fail("regular client flags = %v", present.Flags)
			}
		}
		if present.Key == watcher.SelfPublicKey() && present.Flags&derp.PeerPresentIsMeshPeer == 0 {
			fail("watcher flags = %v, want mesh peer", present.Flags)
		}
		if !present.IPPort.Addr().IsLoopback() || present.IPPort.Port() == 0 {
			fail("peer address = %v, want loopback and non-zero port", present.IPPort)
		}
		wantSnapshot[present.Key] = true
	}

	second := connect(os.Args[1], "future-client", key.DERPMesh{}, false)
	present := requirePresent(recvTimeout(watcher))
	if present.Key != second.SelfPublicKey() || present.AppName != "future-client" {
		fail("future presence mismatch: key=%v app=%q", present.Key, present.AppName)
	}

	secondKey := second.SelfPublicKey()
	must(second.Close())
	gone, ok := recvTimeout(watcher).(derp.PeerGoneMessage)
	if !ok {
		fail("disconnect update was not PeerGoneMessage")
	}
	if gone.Peer != secondKey || gone.Reason != derp.PeerGoneReasonDisconnected {
		fail("disconnect update mismatch: %+v", gone)
	}

	fmt.Println("official Go mesh watcher observed snapshot, app names, flags, and disconnects")
}

func connect(url, appName string, meshKey key.DERPMesh, watch bool) *derphttp.Client {
	client, err := derphttp.NewClient(
		key.NewNode(),
		url,
		func(string, ...any) {},
		netmon.NewStatic(),
	)
	must(err)
	client.AppName = appName
	client.MeshKey = meshKey
	client.WatchConnectionChanges = watch

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(client.Connect(ctx))

	if _, ok := recvTimeout(client).(derp.ServerInfoMessage); !ok {
		fail("first message was not ServerInfoMessage")
	}
	return client
}

func recvTimeout(client *derphttp.Client) any {
	result := make(chan recvResult, 1)
	go func() {
		message, err := client.Recv()
		result <- recvResult{message: message, err: err}
	}()

	select {
	case got := <-result:
		must(got.err)
		return got.message
	case <-time.After(5 * time.Second):
		fail("timed out waiting for DERP message")
		return nil
	}
}

func requirePresent(message any) derp.PeerPresentMessage {
	present, ok := message.(derp.PeerPresentMessage)
	if !ok {
		fail("received %T, want PeerPresentMessage", message)
	}
	return present
}

func remaining(values map[key.NodePublic]bool) int {
	remaining := 0
	for _, found := range values {
		if !found {
			remaining++
		}
	}
	return remaining
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
