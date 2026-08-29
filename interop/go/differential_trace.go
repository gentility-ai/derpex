// Copyright (c) 2026 DERPEX contributors.
// SPDX-License-Identifier: BSD-3-Clause

// Command differential_trace runs deterministic scenarios through unchanged
// official DERP clients and records what each server did. In "oracle" mode it
// starts the pinned Go server and scrapes that server's own varz surface;
// otherwise its arguments name the DERPEX relay and its token-protected
// metrics endpoint. Every trace field is observed: frames seen by the driving
// clients, plus counter deltas snapshotted after each scenario step. Nothing in
// the trace is a constant written by this program.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/net/netmon"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// modeExact compares a step's counter deltas as absolute integers.
	modeExact = "exact"
	// modeSaturating compares only the sign of a step's counter deltas. It is
	// used where the magnitude depends on kernel socket buffer sizes.
	modeSaturating = "saturating"

	// floodPackets overflows both the recipient's socket buffers and the
	// server's per-client send queue while staying far inside the two-second
	// write deadline both servers apply to a stalled recipient.
	floodPackets = 128
	// drainIdle ends the catch-up read of the stalled recipient.
	drainIdle = 500 * time.Millisecond

	recvBudget   = 10 * time.Second
	settleBudget = 10 * time.Second
	settlePoll   = 10 * time.Millisecond
)

type semanticTrace struct {
	Scenarios []scenarioTrace `json:"scenarios"`
}

type scenarioTrace struct {
	Name  string      `json:"name"`
	Steps []stepTrace `json:"steps"`
}

type stepTrace struct {
	Step     string           `json:"step"`
	Mode     string           `json:"mode"`
	Events   []traceEvent     `json:"events"`
	Counters map[string]int64 `json:"counters"`
}

// traceEvent is one semantic observation made by a driving client. Keys are
// stable labels rather than the random public keys they stand for.
type traceEvent struct {
	Kind           string `json:"kind"`
	Client         string `json:"client"`
	Peer           string `json:"peer,omitempty"`
	Reason         string `json:"reason,omitempty"`
	AppName        string `json:"app_name,omitempty"`
	Flags          string `json:"flags,omitempty"`
	Loopback       bool   `json:"loopback,omitempty"`
	Size           int    `json:"size,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	BytesPerSecond int    `json:"bytes_per_second,omitempty"`
	BurstBytes     int    `json:"burst_bytes,omitempty"`
}

type recvResult struct {
	message any
	err     error
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr,
			"usage: differential_trace oracle MESH_KEY | differential_trace DERP_URL MESH_KEY METRICS_URL METRICS_TOKEN")
		os.Exit(2)
	}

	meshKeyHex := os.Args[2]
	meshKey, err := key.ParseDERPMesh(meshKeyHex)
	must(err)

	derpURL, metricsURL, token := os.Args[1], "", ""
	cleanup := func() {}
	if derpURL == "oracle" {
		if len(os.Args) != 3 {
			fail("oracle mode takes only a mesh key")
		}
		derpURL, metricsURL, cleanup = startOracle(meshKeyHex)
	} else {
		if len(os.Args) != 5 {
			fail("DERPEX mode needs a metrics URL and token")
		}
		metricsURL, token = os.Args[3], os.Args[4]
	}
	defer cleanup()

	runner := &runner{
		url:       derpURL,
		meshKey:   meshKey,
		labels:    map[key.NodePublic]string{},
		collector: newCollector(metricsURL, token),
	}

	trace := semanticTrace{Scenarios: []scenarioTrace{
		relayAndDrops(runner),
		duplicateKeys(runner),
		watchPresence(runner),
	}}

	encoded, err := json.Marshal(trace)
	must(err)
	fmt.Printf("DERPEX_TRACE %s\n", encoded)
}

// startOracle runs the pinned Go server together with the same varz surface
// cmd/derper exposes at /debug/varz, without modifying the upstream checkout.
func startOracle(meshKeyHex string) (string, string, func()) {
	server := derpserver.New(key.NewNode(), logger.Discard)
	must(server.SetMeshKey(meshKeyHex))
	expvar.Publish("derp", server.ExpVar(false))

	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(server))
	mux.HandleFunc("/debug/varz", varz.Handler)
	httpServer := httptest.NewServer(mux)

	return httpServer.URL + "/derp", httpServer.URL + "/debug/varz", func() {
		httpServer.CloseClientConnections()
		httpServer.Close()
		must(server.Close())
	}
}

// trackedCounters is the compared subset of server counters, named as Go's
// varz exposes them.
var trackedCounters = buildTrackedCounters()

func buildTrackedCounters() []string {
	names := []string{
		"derp_current_connections",
		"derp_current_dup_client_conns",
		"derp_current_dup_client_keys",
		"derp_got_ping",
		"derp_packets_received",
		"derp_packets_sent",
		"derp_peer_gone_disconnected_frames",
		"derp_peer_gone_not_here_frames",
		"derp_sent_pong",
		"derp_total_dup_client_conns",
		"derp_unknown_frames",
	}
	reasons := []string{
		"dup_client",
		"gone_disconnected",
		"queue_head",
		"queue_tail",
		"unknown_dest",
		"unknown_dest_on_fwd",
		"write_error",
	}
	for _, kind := range []string{"disco", "other"} {
		for _, reason := range reasons {
			names = append(names,
				fmt.Sprintf("derp_packets_dropped{kind=%q,reason=%q}", kind, reason))
		}
	}
	sort.Strings(names)
	return names
}

type collector struct {
	url      string
	token    string
	base     int64
	previous map[string]int64
}

func newCollector(url, token string) *collector {
	collector := &collector{url: url, token: token}
	values := collector.scrape()
	collector.base = values["derp_current_connections"]
	collector.previous = values
	return collector
}

// scrape reads the server's Prometheus surface and returns the tracked subset.
// A tracked counter the server does not publish is a hard failure rather than
// an implicit zero, so a missing counter cannot compare equal to a present one.
func (c *collector) scrape() map[string]int64 {
	request, err := http.NewRequest(http.MethodGet, c.url, nil)
	must(err)
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	response, err := http.DefaultClient.Do(request)
	must(err)
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	must(err)
	if response.StatusCode != http.StatusOK {
		fail("metrics endpoint %s returned %d: %s", c.url, response.StatusCode, body)
	}

	published := parsePrometheus(string(body))
	values := make(map[string]int64, len(trackedCounters))
	for _, name := range trackedCounters {
		value, ok := published[name]
		if !ok {
			fail("metrics endpoint %s does not publish %s", c.url, name)
		}
		values[name] = value
	}
	return values
}

// settle polls until the server reports the expected number of connections, so
// a step's counters are never read while a connect or close is still landing.
func (c *collector) settle(connections int64) map[string]int64 {
	deadline := time.Now().Add(settleBudget)
	for {
		values := c.scrape()
		if values["derp_current_connections"] == c.base+connections {
			return values
		}
		if time.Now().After(deadline) {
			fail("connections settled at %d, want %d",
				values["derp_current_connections"]-c.base, connections)
		}
		time.Sleep(settlePoll)
	}
}

func (c *collector) step(name, mode string, connections int64, events []traceEvent) stepTrace {
	values := c.settle(connections)
	counters := make(map[string]int64, len(trackedCounters))
	for _, metric := range trackedCounters {
		delta := values[metric] - c.previous[metric]
		if mode == modeSaturating {
			delta = sign(delta)
		}
		counters[metric] = delta
	}
	c.previous = values

	if events == nil {
		events = []traceEvent{}
	}
	return stepTrace{Step: name, Mode: mode, Events: events, Counters: counters}
}

func sign(value int64) int64 {
	switch {
	case value > 0:
		return 1
	case value < 0:
		return -1
	default:
		return 0
	}
}

// parsePrometheus reads exposition-format samples into canonically named
// values. Go's varz strips the gauge_/counter_ type prefixes from metric names
// while DERPEX keeps them, and the two order drop labels differently, so both
// the name prefix and the label order are canonicalized here.
func parsePrometheus(body string) map[string]int64 {
	values := map[string]int64{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		separator := strings.LastIndex(line, " ")
		if separator < 0 {
			continue
		}
		value, err := strconv.ParseFloat(line[separator+1:], 64)
		if err != nil {
			continue
		}
		values[canonicalMetric(line[:separator])] = int64(value)
	}
	return values
}

func canonicalMetric(metric string) string {
	name, labels := metric, ""
	if open := strings.Index(metric, "{"); open >= 0 {
		name = metric[:open]
		labels = canonicalLabels(strings.TrimSuffix(metric[open+1:], "}"))
	}

	if rest, ok := strings.CutPrefix(name, "derp_"); ok {
		for _, prefix := range []string{"gauge_", "counter_", "labelmap_", "histogram_"} {
			if trimmed, ok := strings.CutPrefix(rest, prefix); ok {
				rest = trimmed
				break
			}
		}
		name = "derp_" + rest
	}
	return name + labels
}

func canonicalLabels(labels string) string {
	if labels == "" {
		return ""
	}
	pairs := strings.Split(labels, ",")
	sort.Strings(pairs)
	return "{" + strings.Join(pairs, ",") + "}"
}

type runner struct {
	url         string
	meshKey     key.DERPMesh
	labels      map[key.NodePublic]string
	collector   *collector
	connections int64
}

func (r *runner) step(name, mode string, events []traceEvent) stepTrace {
	return r.collector.step(name, mode, r.connections, events)
}

func (r *runner) connect(
	label, appName string,
	private key.NodePrivate,
	meshKey key.DERPMesh,
	watch bool,
) (*derphttp.Client, traceEvent) {
	client, err := derphttp.NewClient(private, r.url, logger.Discard, netmon.NewStatic())
	must(err)
	client.AppName = appName
	client.MeshKey = meshKey
	client.WatchConnectionChanges = watch

	ctx, cancel := context.WithTimeout(context.Background(), recvBudget)
	defer cancel()
	must(client.Connect(ctx))

	message := recvTimeout(client)
	info, ok := message.(derp.ServerInfoMessage)
	if !ok {
		fail("first DERP message was %T, want derp.ServerInfoMessage", message)
	}

	// Two connections can share one public key, and the first label registered
	// for a key is the one peer references resolve to.
	if _, ok := r.labels[client.SelfPublicKey()]; !ok {
		r.labels[client.SelfPublicKey()] = label
	}
	r.connections++
	return client, traceEvent{
		Kind:           "server_info",
		Client:         label,
		BytesPerSecond: info.TokenBucketBytesPerSecond,
		BurstBytes:     info.TokenBucketBytesBurst,
	}
}

func (r *runner) close(client *derphttp.Client) {
	must(client.Close())
	r.connections--
}

func (r *runner) label(peer key.NodePublic) string {
	label, ok := r.labels[peer]
	if !ok {
		fail("no label registered for peer %v", peer)
	}
	return label
}

func (r *runner) packetEvent(client string, packet derp.ReceivedPacket) traceEvent {
	digest := sha256.Sum256(packet.Data)
	return traceEvent{
		Kind:   "packet",
		Client: client,
		Peer:   r.label(packet.Source),
		Size:   len(packet.Data),
		SHA256: hex.EncodeToString(digest[:]),
	}
}

func (r *runner) peerGoneEvent(client string, gone derp.PeerGoneMessage) traceEvent {
	return traceEvent{
		Kind:   "peer_gone",
		Client: client,
		Peer:   r.label(gone.Peer),
		Reason: goneReason(gone.Reason),
	}
}

func (r *runner) presenceEvent(client string, present derp.PeerPresentMessage) traceEvent {
	return traceEvent{
		Kind:     "peer_present",
		Client:   client,
		Peer:     r.label(present.Key),
		AppName:  present.AppName,
		Flags:    presenceFlags(present.Flags),
		Loopback: present.IPPort.Addr().IsLoopback() && present.IPPort.Port() != 0,
	}
}

func goneReason(reason derp.PeerGoneReasonType) string {
	switch reason {
	case derp.PeerGoneReasonDisconnected:
		return "disconnected"
	case derp.PeerGoneReasonNotHere:
		return "not_here"
	default:
		fail("unexpected peer-gone reason %d", int(reason))
		return ""
	}
}

func presenceFlags(flags derp.PeerPresentFlags) string {
	names := []string{}
	if flags&derp.PeerPresentIsRegular != 0 {
		names = append(names, "regular")
	}
	if flags&derp.PeerPresentIsMeshPeer != 0 {
		names = append(names, "mesh_peer")
	}
	if flags&derp.PeerPresentIsProber != 0 {
		names = append(names, "prober")
	}
	return strings.Join(names, "|")
}

// relayAndDrops relays packets, answers a ping, reports an unknown destination,
// and then overruns a recipient that has stopped reading.
func relayAndDrops(r *runner) scenarioTrace {
	scenario := scenarioTrace{Name: "relay_and_drops"}

	first, firstInfo := r.connect("first", "", key.NewNode(), key.DERPMesh{}, false)
	second, secondInfo := r.connect("second", "", key.NewNode(), key.DERPMesh{}, false)
	stalled, stalledInfo := r.connect("stalled", "", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("connect_clients", modeExact,
		[]traceEvent{firstInfo, secondInfo, stalledInfo}))

	payloads := [][]byte{
		{},
		[]byte("differential DERP trace"),
		bytes.Repeat([]byte{0xa5}, derp.MaxPacketSize),
	}
	relayed := []traceEvent{}
	for _, payload := range payloads {
		must(first.Send(second.SelfPublicKey(), payload))
		packet := requirePacket(recvTimeout(second), first.SelfPublicKey(), payload)
		relayed = append(relayed, r.packetEvent("second", packet))
	}
	scenario.add(r.step("relay_payloads", modeExact, relayed))

	pong := pingPong(first, [8]byte{0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47})
	digest := sha256.Sum256(pong[:])
	scenario.add(r.step("ping_pong", modeExact, []traceEvent{{
		Kind:   "pong",
		Client: "first",
		Size:   len(pong),
		SHA256: hex.EncodeToString(digest[:]),
	}}))

	unknown := key.NewNode().Public()
	r.labels[unknown] = "unknown"
	discoPacket := unknown.AppendTo([]byte(disco.Magic))
	discoPacket = append(discoPacket, make([]byte, disco.NonceLen)...)
	must(second.Send(unknown, discoPacket))
	gone := requirePeerGone(recvTimeout(second), unknown)
	scenario.add(r.step("unknown_destination", modeExact,
		[]traceEvent{r.peerGoneEvent("second", gone)}))

	// The stalled client never reads, so its socket buffers and then the
	// server's per-client send queue fill and the server starts dropping.
	flood := bytes.Repeat([]byte{0x5a}, derp.MaxPacketSize)
	for range floodPackets {
		must(second.Send(stalled.SelfPublicKey(), flood))
	}
	// A ping answered on the sender's own connection proves the server has
	// read and routed every flood frame ahead of it, so the drops all land in
	// this step rather than leaking into the next one.
	barrier(second)
	scenario.add(r.step("flood_stalled_recipient", modeSaturating, nil))

	drain(stalled)
	r.close(stalled)
	scenario.add(r.step("drain_stalled_recipient", modeSaturating, nil))

	firstPublic := first.SelfPublicKey()
	r.close(first)
	scenario.add(r.step("close_first", modeExact, []traceEvent{
		r.peerGoneEvent("second", requirePeerGone(recvTimeout(second), firstPublic)),
	}))

	r.close(second)
	scenario.add(r.step("close_second", modeExact, nil))
	return scenario
}

// duplicateKeys drives two connections sharing one public key and observes
// which of them the server routes to.
func duplicateKeys(r *runner) scenarioTrace {
	scenario := scenarioTrace{Name: "duplicate_keys"}

	duplicate := key.NewNode()
	r.labels[duplicate.Public()] = "duplicate"
	older, olderInfo := r.connect("older", "", duplicate, key.DERPMesh{}, false)
	newer, newerInfo := r.connect("newer", "", duplicate, key.DERPMesh{}, false)
	sender, senderInfo := r.connect("sender", "", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("connect_duplicates", modeExact,
		[]traceEvent{olderInfo, newerInfo, senderInfo}))

	newestPayload := []byte("newest duplicate")
	must(sender.Send(duplicate.Public(), newestPayload))
	scenario.add(r.step("newest_connection_receives", modeExact, []traceEvent{
		r.packetEvent("newer",
			requirePacket(recvTimeout(newer), sender.SelfPublicKey(), newestPayload)),
	}))

	olderPayload := []byte("older active")
	must(older.Send(sender.SelfPublicKey(), olderPayload))
	scenario.add(r.step("older_connection_writes", modeExact, []traceEvent{
		r.packetEvent("sender",
			requirePacket(recvTimeout(sender), duplicate.Public(), olderPayload)),
	}))

	lastPayload := []byte("last writer")
	must(sender.Send(duplicate.Public(), lastPayload))
	scenario.add(r.step("last_writer_receives", modeExact, []traceEvent{
		r.packetEvent("older",
			requirePacket(recvTimeout(older), sender.SelfPublicKey(), lastPayload)),
	}))

	r.close(older)
	r.close(newer)
	scenario.add(r.step("close_duplicate_connections", modeExact, []traceEvent{
		r.peerGoneEvent("sender",
			requirePeerGone(recvTimeout(sender), duplicate.Public())),
	}))

	r.close(sender)
	return scenario
}

// watchPresence drives a trusted mesh watcher over the presence snapshot, a
// later arrival, and a departure.
func watchPresence(r *runner) scenarioTrace {
	scenario := scenarioTrace{Name: "watch_presence"}

	alpha, alphaInfo := r.connect("alpha", "alpha-app", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("connect_regular", modeExact, []traceEvent{alphaInfo}))

	watcher, watcherInfo := r.connect("watcher", "", key.NewNode(), r.meshKey, true)
	snapshot := []traceEvent{}
	for range 2 {
		snapshot = append(snapshot,
			r.presenceEvent("watcher", requirePresent(recvTimeout(watcher))))
	}
	// The initial snapshot enumerates connected peers in unspecified order.
	sortEvents(snapshot)
	scenario.add(r.step("connect_watcher", modeExact,
		append([]traceEvent{watcherInfo}, snapshot...)))

	beta, betaInfo := r.connect("beta", "beta-app", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("present_second_regular", modeExact, []traceEvent{
		betaInfo,
		r.presenceEvent("watcher", requirePresent(recvTimeout(watcher))),
	}))

	betaPublic := beta.SelfPublicKey()
	r.close(beta)
	scenario.add(r.step("close_second_regular", modeExact, []traceEvent{
		r.peerGoneEvent("watcher", requirePeerGone(recvTimeout(watcher), betaPublic)),
	}))

	r.close(watcher)
	r.close(alpha)
	return scenario
}

func (s *scenarioTrace) add(step stepTrace) {
	s.Steps = append(s.Steps, step)
}

func sortEvents(events []traceEvent) {
	sort.Slice(events, func(i, j int) bool {
		left, err := json.Marshal(events[i])
		must(err)
		right, err := json.Marshal(events[j])
		must(err)
		return string(left) < string(right)
	})
}

// barrier round-trips a ping on one client's own connection. A DERP server
// reads a connection's frames in order, so the pong proves every frame that
// client sent earlier has already been routed and accounted for.
func barrier(client *derphttp.Client) {
	_ = pingPong(client, [8]byte{0x9b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72})
}

func pingPong(client *derphttp.Client, data [8]byte) derp.PongMessage {
	must(client.SendPing(data))
	pong, ok := recvTimeout(client).(derp.PongMessage)
	if !ok || pong != derp.PongMessage(data) {
		fail("ping was not answered with the same pong payload")
	}
	return pong
}

// drain lets a stalled recipient catch up so its send queue is empty before it
// disconnects, keeping the shutdown path free of queue-pressure drops.
func drain(client *derphttp.Client) {
	for {
		received := make(chan recvResult, 1)
		go func() {
			message, err := client.Recv()
			received <- recvResult{message: message, err: err}
		}()

		select {
		case result := <-received:
			if result.err != nil {
				return
			}
		case <-time.After(drainIdle):
			return
		}
	}
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
	case <-time.After(recvBudget):
		fail("timed out waiting for DERP message")
		return nil
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

func requirePeerGone(message any, peer key.NodePublic) derp.PeerGoneMessage {
	gone, ok := message.(derp.PeerGoneMessage)
	if !ok {
		fail("received %T, want derp.PeerGoneMessage", message)
	}
	if gone.Peer != peer {
		fail("peer-gone key mismatch")
	}
	return gone
}

func requirePresent(message any) derp.PeerPresentMessage {
	present, ok := message.(derp.PeerPresentMessage)
	if !ok {
		fail("received %T, want derp.PeerPresentMessage", message)
	}
	return present
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fail(format string, arguments ...any) {
	panic(fmt.Sprintf(format, arguments...))
}
