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

	// A hundred clients arrive while three watchers are connected, and a
	// fourth joins afterwards. Every watcher must learn about every one of
	// them: presence is state, not traffic, so none of it may be dropped.
	// This mirrors TestWatch in derp_test.go.
	const clientCount = 100

	watchers := []*derphttp.Client{watcher}
	for range 2 {
		extra := connect(os.Args[1], "", meshKey, true)
		defer extra.Close()
		watchers = append(watchers, extra)
	}

	crowd := make([]*derphttp.Client, 0, clientCount)
	expected := make(map[key.NodePublic]bool, clientCount)
	for index := range clientCount {
		client := connect(os.Args[1], fmt.Sprintf("crowd-%d", index), key.DERPMesh{}, false)
		defer client.Close()
		crowd = append(crowd, client)
		expected[client.SelfPublicKey()] = true
	}

	for index, seeing := range watchers {
		seen := collectPresent(seeing, expected)
		for peer := range expected {
			if !seen[peer] {
				fail("watcher %d never saw peer %v", index, peer)
			}
		}
	}

	// The late joiner gets the whole region in its snapshot, crowd included.
	late := connect(os.Args[1], "", meshKey, true)
	defer late.Close()
	snapshot := collectPresent(late, expected)
	for peer := range expected {
		if !snapshot[peer] {
			fail("late watcher's snapshot omitted peer %v", peer)
		}
	}

	fmt.Printf("official Go mesh watchers each saw all %d clients, and a late joiner saw them in its snapshot\n", len(crowd))
	fmt.Println("official Go mesh watcher observed snapshot, app names, flags, and disconnects")
}

// collectPresent reads lifecycle frames until every wanted peer has been seen
// present, ignoring peers and frames it is not waiting for.
func collectPresent(client *derphttp.Client, wanted map[key.NodePublic]bool) map[key.NodePublic]bool {
	seen := make(map[key.NodePublic]bool, len(wanted))
	for len(seen) < len(wanted) {
		message := recvTimeout(client)
		present, ok := message.(derp.PeerPresentMessage)
		if !ok {
			continue
		}
		if wanted[present.Key] {
			seen[present.Key] = true
		}
	}
	return seen
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
