// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command protocol_edges uses the official low-level DERP client around raw
// frame writes to cover behavior the high-level client intentionally forbids.
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
)

type connection struct {
	client *derp.Client
	conn   net.Conn
	writer *bufio.Writer
}

func connect(rawURL string) *connection {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		panic(err)
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Upgrade", "DERP")
	request.Header.Set("Connection", "Upgrade")
	if err := request.Write(writer); err != nil {
		panic(err)
	}
	if err := writer.Flush(); err != nil {
		panic(err)
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		panic(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		panic(fmt.Sprintf("upgrade status was %s", response.Status))
	}

	client, err := derp.NewClient(
		key.NewNode(),
		conn,
		bufio.NewReadWriter(reader, writer),
		func(string, ...any) {},
	)
	if err != nil {
		panic(err)
	}
	message, err := client.Recv()
	if err != nil {
		panic(err)
	}
	if _, ok := message.(derp.ServerInfoMessage); !ok {
		panic(fmt.Sprintf("first DERP message was %T", message))
	}
	return &connection{client: client, conn: conn, writer: writer}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: protocol_edges DERP_URL")
		os.Exit(2)
	}

	unknown := connect(os.Args[1])
	const unknownLength = 2 << 20
	if err := derp.WriteFrameHeader(unknown.writer, derp.FrameType(0xfe), unknownLength); err != nil {
		panic(err)
	}
	chunk := make([]byte, 4096)
	for sent := 0; sent < unknownLength; sent += len(chunk) {
		if _, err := unknown.writer.Write(chunk); err != nil {
			panic(err)
		}
	}
	if err := unknown.writer.Flush(); err != nil {
		panic(err)
	}
	payload := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := unknown.client.SendPing(payload); err != nil {
		panic(err)
	}

	unknown.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	message, err := unknown.client.Recv()
	if err != nil {
		panic(err)
	}
	pong, ok := message.(derp.PongMessage)
	if !ok || [8]byte(pong) != payload {
		panic(fmt.Sprintf("received %T, want matching derp.PongMessage", message))
	}
	if err := unknown.conn.Close(); err != nil {
		panic(err)
	}

	oversize := connect(os.Args[1])
	oversize.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	length := uint32(derp.KeyLen + derp.MaxPacketSize + 1)
	if err := derp.WriteFrameHeader(oversize.writer, derp.FrameSendPacket, length); err != nil {
		panic(err)
	}
	if err := oversize.writer.Flush(); err != nil {
		panic(err)
	}
	if _, err := oversize.client.Recv(); err == nil {
		panic("oversize packet header did not close the connection")
	}
	oversize.conn.Close()

	fmt.Println("official low-level client discarded a 2-MiB unknown frame and rejected an oversize packet header")
}
