// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command prober_smoke runs the official DERP prober's 100 MB, 30-packet
// in-flight relay pattern through a running DERPEX listener.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

const (
	probeSize          = 100_000_000
	inFlightLimit      = 30
	maxLostPackets     = inFlightLimit
	receiveIdleTimeout = 2 * time.Second
)

type receiveEvent struct {
	packet derp.ReceivedPacket
	err    error
}

func connect(ctx context.Context, url string) *derphttp.Client {
	client, err := derphttp.NewClient(key.NewNode(), url, func(string, ...any) {}, netmon.NewStatic())
	if err != nil {
		panic(err)
	}
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

func packetCount(size int) int {
	return (size + derp.MaxPacketSize - 1) / derp.MaxPacketSize
}

func packetForSequence(sequence int) []byte {
	remaining := probeSize - sequence*derp.MaxPacketSize
	packet := make([]byte, min(remaining, derp.MaxPacketSize))
	binary.BigEndian.PutUint64(packet, uint64(sequence))

	generator := rand.New(rand.NewSource(int64(sequence)))
	if _, err := generator.Read(packet[8:]); err != nil {
		panic(err)
	}
	return packet
}

func releaseTokens(ctx context.Context, inFlight <-chan struct{}, count int) error {
	for index := 0; index < count; index++ {
		select {
		case <-inFlight:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func resetTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(receiveIdleTimeout)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: prober_smoke DERP_URL")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sender := connect(ctx, os.Args[1])
	defer sender.Close()
	receiver := connect(ctx, os.Args[1])
	defer receiver.Close()

	totalPackets := packetCount(probeSize)
	inFlight := make(chan struct{}, inFlightLimit)
	sendDone := make(chan error, 1)
	receiveEvents := make(chan receiveEvent, 1)

	go func() {
		for sequence := 0; sequence < totalPackets; sequence++ {
			select {
			case inFlight <- struct{}{}:
			case <-ctx.Done():
				sendDone <- ctx.Err()
				return
			}
			packet := packetForSequence(sequence)
			if err := sender.Send(receiver.SelfPublicKey(), packet); err != nil {
				sendDone <- fmt.Errorf("sending packet %d: %w", sequence, err)
				return
			}
		}
		sendDone <- nil
	}()

	go func() {
		for {
			message, err := receiver.Recv()
			if err != nil {
				select {
				case receiveEvents <- receiveEvent{err: err}:
				case <-ctx.Done():
				}
				return
			}
			switch value := message.(type) {
			case derp.ReceivedPacket:
				select {
				case receiveEvents <- receiveEvent{packet: value}:
				case <-ctx.Done():
					return
				}
			case derp.KeepAliveMessage:
			default:
			}
		}
	}()

	// DERP is a lossy datagram relay. The upstream prober acknowledges that
	// DERP does not guarantee reliable, ordered delivery even though its probe
	// assumes it (tailscale/prober/derp.go:839-843). DERPEX ADR 0001 also permits
	// contention tail-drops, so tolerate bounded loss while still rejecting
	// corruption and reordering on this single TCP path.
	seen := make([]bool, totalPackets)
	expected := 0
	relayedBytes := 0
	relayedPackets := 0
	lostPackets := 0
	reorderedPackets := 0
	corruptedPackets := 0
	senderFinished := false
	sendDoneChannel := (<-chan error)(sendDone)
	var idleTimer *time.Timer
	var idleTimerChannel <-chan time.Time
	defer func() {
		if idleTimer != nil {
			idleTimer.Stop()
		}
	}()

	printSummary := func() {
		fmt.Printf(
			"official DERP prober relayed %d bytes through DERPEX (packets=%d lost=%d reordered=%d corrupted=%d)\n",
			relayedBytes,
			relayedPackets,
			lostPackets,
			reorderedPackets,
			corruptedPackets,
		)
	}

	for {
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case err := <-sendDoneChannel:
			if err != nil {
				panic(err)
			}
			senderFinished = true
			sendDoneChannel = nil
			idleTimer = time.NewTimer(receiveIdleTimeout)
			idleTimerChannel = idleTimer.C
		case event := <-receiveEvents:
			if event.err != nil {
				panic(fmt.Errorf("after %d data packets: %w", relayedPackets, event.err))
			}
			if senderFinished {
				resetTimer(idleTimer)
			}

			packet := event.packet
			if packet.Source != sender.SelfPublicKey() {
				panic(fmt.Sprintf("packet %d has unexpected source", relayedPackets))
			}
			if len(packet.Data) < 8 {
				corruptedPackets++
				panic(fmt.Sprintf("data packet %d is too short", relayedPackets))
			}

			sequence64 := binary.BigEndian.Uint64(packet.Data[:8])
			if sequence64 >= uint64(totalPackets) {
				corruptedPackets++
				panic(fmt.Sprintf("data packet %d has invalid sequence %d", relayedPackets, sequence64))
			}
			sequence := int(sequence64)
			if !bytes.Equal(packet.Data, packetForSequence(sequence)) {
				corruptedPackets++
				panic(fmt.Sprintf("sequence %d payload is corrupted", sequence))
			}
			if seen[sequence] || sequence < expected {
				reorderedPackets++
				panic(fmt.Sprintf("sequence %d is reordered or duplicated; expected %d", sequence, expected))
			}

			lost := sequence - expected
			if err := releaseTokens(ctx, inFlight, lost+1); err != nil {
				panic(err)
			}
			lostPackets += lost
			if lostPackets > maxLostPackets {
				panic(fmt.Sprintf("lost %d packets; budget is %d", lostPackets, maxLostPackets))
			}

			seen[sequence] = true
			expected = sequence + 1
			relayedPackets++
			relayedBytes += len(packet.Data)
			if sequence == totalPackets-1 {
				printSummary()
				return
			}
		case <-idleTimerChannel:
			remaining := totalPackets - expected
			if err := releaseTokens(ctx, inFlight, remaining); err != nil {
				panic(err)
			}
			lostPackets += remaining
			if lostPackets > maxLostPackets {
				panic(fmt.Sprintf("lost %d packets; budget is %d", lostPackets, maxLostPackets))
			}
			printSummary()
			return
		}
	}
}
