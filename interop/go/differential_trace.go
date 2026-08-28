// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command differential_trace runs the same deterministic scenario through
// unchanged official DERP clients. In "oracle" mode it starts the pinned Go
// server; otherwise its argument is the DERPEX URL. The emitted trace excludes
// random keys and timing while retaining every semantic outcome under test.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type semanticTrace struct {
	ServerInfo       []serverInfoEvent `json:"server_info"`
	RelayedPackets   []packetEvent     `json:"relayed_packets"`
	PeerGone         []peerGoneEvent   `json:"peer_gone"`
	DuplicateRouting []string          `json:"duplicate_routing"`
}

type serverInfoEvent struct {
	Client         string `json:"client"`
	BytesPerSecond int    `json:"bytes_per_second"`
	BurstBytes     int    `json:"burst_bytes"`
}

type packetEvent struct {
	Source string `json:"source"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type peerGoneEvent struct {
	Peer   string `json:"peer"`
	Reason int    `json:"reason"`
}

type recvResult struct {
	message any
	err     error
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: differential_trace oracle|DERP_URL")
		os.Exit(2)
	}

	url, cleanup := target(os.Args[1])
	defer cleanup()

	trace := runScenario(url)
	encoded, err := json.Marshal(trace)
	must(err)
	fmt.Printf("DERPEX_TRACE %s\n", encoded)
}

func target(argument string) (string, func()) {
	if argument != "oracle" {
		return argument, func() {}
	}

	server := derpserver.New(key.NewNode(), logger.Discard)
	httpServer := httptest.NewServer(derpserver.Handler(server))
	return httpServer.URL + "/derp", func() {
		httpServer.CloseClientConnections()
		httpServer.Close()
		must(server.Close())
	}
}

func runScenario(url string) semanticTrace {
	trace := semanticTrace{}

	firstKey := key.NewNode()
	secondKey := key.NewNode()
	first, firstInfo := connect(url, firstKey)
	second, secondInfo := connect(url, secondKey)
	trace.ServerInfo = append(
		trace.ServerInfo,
		serverInfo("first", firstInfo),
		serverInfo("second", secondInfo),
	)

	payloads := [][]byte{
		{},
		[]byte("differential DERP trace"),
		bytes.Repeat([]byte{0xa5}, derp.MaxPacketSize),
	}
	for _, payload := range payloads {
		must(first.Send(second.SelfPublicKey(), payload))
		packet := requirePacket(recvTimeout(second), first.SelfPublicKey(), payload)
		trace.RelayedPackets = append(trace.RelayedPackets, packetEventFor("first", packet.Data))
	}

	firstPublic := first.SelfPublicKey()
	must(first.Close())
	trace.PeerGone = append(
		trace.PeerGone,
		requirePeerGone(recvTimeout(second), firstPublic, "first"),
	)

	unknownKey := key.NewNode().Public()
	discoPacket := unknownKey.AppendTo([]byte(disco.Magic))
	discoPacket = append(discoPacket, make([]byte, disco.NonceLen)...)
	must(second.Send(unknownKey, discoPacket))
	trace.PeerGone = append(
		trace.PeerGone,
		requirePeerGone(recvTimeout(second), unknownKey, "unknown"),
	)
	must(second.Close())

	duplicateKey := key.NewNode()
	older, _ := connect(url, duplicateKey)
	newer, _ := connect(url, duplicateKey)
	sender, _ := connect(url, key.NewNode())

	must(sender.Send(duplicateKey.Public(), []byte("newest duplicate")))
	requirePacket(recvTimeout(newer), sender.SelfPublicKey(), []byte("newest duplicate"))
	trace.DuplicateRouting = append(trace.DuplicateRouting, "newest_connection")

	must(older.Send(sender.SelfPublicKey(), []byte("older active")))
	requirePacket(recvTimeout(sender), duplicateKey.Public(), []byte("older active"))
	trace.DuplicateRouting = append(trace.DuplicateRouting, "older_wrote")

	must(sender.Send(duplicateKey.Public(), []byte("last writer")))
	requirePacket(recvTimeout(older), sender.SelfPublicKey(), []byte("last writer"))
	trace.DuplicateRouting = append(trace.DuplicateRouting, "last_writer_receives")

	must(sender.Close())
	must(newer.Close())
	must(older.Close())
	return trace
}

func connect(url string, private key.NodePrivate) (*derphttp.Client, derp.ServerInfoMessage) {
	client, err := derphttp.NewClient(private, url, logger.Discard, netmon.NewStatic())
	must(err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(client.Connect(ctx))

	message := recvTimeout(client)
	info, ok := message.(derp.ServerInfoMessage)
	if !ok {
		fail("first DERP message was %T, want derp.ServerInfoMessage", message)
	}
	return client, info
}

func recvTimeout(client *derphttp.Client) any {
	received := make(chan recvResult, 1)
	go func() {
		message, err := client.Recv()
		received <- recvResult{message: message, err: err}
	}()

	select {
	case result := <-received:
		must(result.err)
		return result.message
	case <-time.After(10 * time.Second):
		fail("timed out waiting for DERP message")
		return nil
	}
}

func serverInfo(client string, info derp.ServerInfoMessage) serverInfoEvent {
	return serverInfoEvent{
		Client:         client,
		BytesPerSecond: info.TokenBucketBytesPerSecond,
		BurstBytes:     info.TokenBucketBytesBurst,
	}
}

func packetEventFor(source string, payload []byte) packetEvent {
	digest := sha256.Sum256(payload)
	return packetEvent{
		Source: source,
		Size:   len(payload),
		SHA256: hex.EncodeToString(digest[:]),
	}
}

func requirePacket(message any, source key.NodePublic, payload []byte) derp.ReceivedPacket {
	packet, ok := message.(derp.ReceivedPacket)
	if !ok {
		fail("received %T, want derp.ReceivedPacket", message)
	}
	if packet.Source != source || !bytes.Equal(packet.Data, payload) {
		fail("relayed packet source or payload mismatch")
	}
	return packet
}

func requirePeerGone(message any, peer key.NodePublic, label string) peerGoneEvent {
	gone, ok := message.(derp.PeerGoneMessage)
	if !ok {
		fail("received %T, want derp.PeerGoneMessage", message)
	}
	if gone.Peer != peer {
		fail("peer-gone key mismatch")
	}
	return peerGoneEvent{Peer: label, Reason: int(gone.Reason)}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fail(format string, arguments ...any) {
	panic(fmt.Sprintf(format, arguments...))
}
