// Copyright (c) 2026 James Tippett
// SPDX-License-Identifier: MIT

// stun_smoke sends the official Tailscale STUN request and parses the response
// with the official implementation. Run it from the pinned Tailscale module.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"tailscale.com/net/stun"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: stun_smoke host:port")
		os.Exit(2)
	}

	server, err := net.ResolveUDPAddr("udp", os.Args[1])
	must(err)

	conn, err := net.DialUDP("udp", nil, server)
	must(err)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(3 * time.Second)))

	txID := stun.NewTxID()
	_, err = conn.Write(stun.Request(txID))
	must(err)

	packet := make([]byte, 2048)
	n, err := conn.Read(packet)
	must(err)

	gotTxID, mapped, err := stun.ParseResponse(packet[:n])
	must(err)
	if gotTxID != txID {
		fail("transaction ID mismatch: got %x, want %x", gotTxID, txID)
	}

	local := conn.LocalAddr().(*net.UDPAddr)
	localIP, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		fail("invalid local IP %v", local.IP)
	}
	if mapped.Addr() != localIP.Unmap() || mapped.Port() != uint16(local.Port) {
		fail("mapped address mismatch: got %v, want %v", mapped, local)
	}

	fmt.Println("official Go STUN client observed its XOR-mapped UDP address")
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
