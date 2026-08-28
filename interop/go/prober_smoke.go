// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command prober_smoke runs the official DERP prober's 100 MB, 30-packet
// in-flight relay pattern through a running DERPEX listener.
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

const probeSize = 100_000_000

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

func packetsForSize(size int) [][]byte {
	packets := make([][]byte, 0, (size+derp.MaxPacketSize-1)/derp.MaxPacketSize)
	for remaining := size; remaining > 0; remaining -= derp.MaxPacketSize {
		packet := make([]byte, min(remaining, derp.MaxPacketSize))
		if _, err := crand.Read(packet); err != nil {
			panic(err)
		}
		packets = append(packets, packet)
	}
	return packets
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

	packets := packetsForSize(probeSize)
	inFlight := make(chan struct{}, 30)
	sendDone := make(chan error, 1)
	receiveDone := make(chan error, 1)

	go func() {
		for index, packet := range packets {
			select {
			case inFlight <- struct{}{}:
			case <-ctx.Done():
				sendDone <- ctx.Err()
				return
			}
			if err := sender.Send(receiver.SelfPublicKey(), packet); err != nil {
				sendDone <- fmt.Errorf("sending packet %d: %w", index, err)
				return
			}
		}
		sendDone <- nil
	}()

	go func() {
		index := 0
		for index < len(packets) {
			message, err := receiver.Recv()
			if err != nil {
				receiveDone <- fmt.Errorf("after %d data packets: %w", index, err)
				return
			}
			switch value := message.(type) {
			case derp.ReceivedPacket:
				<-inFlight
				if value.Source != sender.SelfPublicKey() {
					receiveDone <- fmt.Errorf("packet %d has unexpected source", index)
					return
				}
				if !bytes.Equal(value.Data, packets[index]) {
					receiveDone <- fmt.Errorf("packet %d payload mismatch", index)
					return
				}
				index++
			case derp.KeepAliveMessage:
			default:
			}
		}
		receiveDone <- nil
	}()

	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case err := <-sendDone:
		if err != nil {
			panic(err)
		}
	case err := <-receiveDone:
		if err != nil {
			panic(err)
		}
		fmt.Printf("official DERP prober relayed %d bytes through DERPEX\n", probeSize)
		return
	}

	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case err := <-receiveDone:
		if err != nil {
			panic(err)
		}
		fmt.Printf("official DERP prober relayed %d bytes through DERPEX\n", probeSize)
	}
}
