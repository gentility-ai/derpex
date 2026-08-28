// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command mesh_control_smoke uses unchanged official DERP HTTP clients to
// exercise trusted packet forwarding and duplicate-peer closure.
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

type recvResult struct {
	message any
	err     error
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mesh_control_smoke DERP_URL MESH_KEY")
		os.Exit(2)
	}

	meshKey, err := key.ParseDERPMesh(os.Args[2])
	must(err)

	destination := connect(os.Args[1], key.NewNode(), key.DERPMesh{})
	defer destination.Close()
	mesh := connect(os.Args[1], key.NewNode(), meshKey)
	defer mesh.Close()

	assertedSource := key.NewNode().Public()
	payload := []byte("forwarded by an official trusted mesh client")
	must(mesh.ForwardPacket(assertedSource, destination.SelfPublicKey(), payload))

	packet, ok := recvTimeout(destination).(derp.ReceivedPacket)
	if !ok {
		fail("forward destination received an unexpected message type")
	}
	if packet.Source != assertedSource || !bytes.Equal(packet.Data, payload) {
		fail("forwarded packet did not preserve its asserted source and payload")
	}

	unknown := key.NewNode().Public()
	discoPacket := unknown.AppendTo([]byte(disco.Magic))
	discoPacket = append(discoPacket, make([]byte, disco.NonceLen)...)
	must(mesh.ForwardPacket(assertedSource, unknown, discoPacket))

	gone, ok := recvTimeout(mesh).(derp.PeerGoneMessage)
	if !ok || gone.Peer != unknown || gone.Reason != derp.PeerGoneReasonNotHere {
		fail("unknown forwarded disco packet did not produce PeerGone(NotHere)")
	}

	targetPrivate := key.NewNode()
	firstTarget := connect(os.Args[1], targetPrivate, key.DERPMesh{})
	defer firstTarget.Close()
	secondTarget := connect(os.Args[1], targetPrivate, key.DERPMesh{})
	defer secondTarget.Close()

	must(mesh.ClosePeer(firstTarget.SelfPublicKey()))
	requireRecvError(firstTarget)
	requireRecvError(secondTarget)

	fmt.Println("official Go mesh client forwarded asserted sources and closed every duplicate peer")
}

func connect(url string, private key.NodePrivate, meshKey key.DERPMesh) *derphttp.Client {
	client, err := derphttp.NewClient(
		private,
		url,
		func(string, ...any) {},
		netmon.NewStatic(),
	)
	must(err)
	client.MeshKey = meshKey

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

func requireRecvError(client *derphttp.Client) {
	result := make(chan error, 1)
	go func() {
		_, err := client.Recv()
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			fail("closed peer received a message instead of a connection error")
		}
	case <-time.After(5 * time.Second):
		fail("timed out waiting for closed peer connection error")
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
