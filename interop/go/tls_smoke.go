// Copyright (c) 2026 Gentility AI & DERPEX contributors.
// SPDX-License-Identifier: MIT

// Command tls_smoke proves TLS 1.3 metacertificate fast start using an
// unchanged official DERP HTTP client.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tls_smoke DERP_URL CERTIFICATE_PEM")
		os.Exit(2)
	}

	certificate, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		panic("could not load test root certificate")
	}

	client, err := derphttp.NewClient(key.NewNode(), os.Args[1], func(string, ...any) {}, netmon.NewStatic())
	if err != nil {
		panic(err)
	}
	client.TLSConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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

	state, ok := client.TLSConnectionState()
	if !ok || state.Version != tls.VersionTLS13 {
		panic("unexpected TLS version")
	}
	if client.ServerPublicKey().IsZero() {
		panic("official client did not discover the DERP key from the metacertificate")
	}

	fmt.Println("official Go client used TLS 1.3 metacertificate fast start")
}
