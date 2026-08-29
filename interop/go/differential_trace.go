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
	// ordinaryFloodPackets first fills the stalled recipient's socket buffers
	// and then overruns its ordinary send queue.
	ordinaryFloodPackets = 128
	// discoFloodPackets overruns the separate disco send queue, which by then
	// cannot drain at all because the writer is blocked on the ordinary one.
	discoFloodPackets = 64
	// drainIdle ends the catch-up read of the stalled recipient.
	drainIdle = 500 * time.Millisecond

	recvBudget    = 10 * time.Second
	settleBudget  = 10 * time.Second
	settlePoll    = 10 * time.Millisecond
	scrapeTimeout = 15 * time.Second
)

type semanticTrace struct {
	Scenarios []scenarioTrace `json:"scenarios"`
}

type scenarioTrace struct {
	Name  string      `json:"name"`
	Steps []stepTrace `json:"steps"`
}

type stepTrace struct {
	Step string `json:"step"`
	// Saturating names the counters this step compares by sign rather than by
	// value, because their magnitude depends on kernel socket buffer sizes.
	// Every other tracked counter in the step is compared exactly.
	Saturating []string         `json:"saturating"`
	Events     []traceEvent     `json:"events"`
	Counters   map[string]int64 `json:"counters"`
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
		raw:       map[string]map[string]int64{},
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
	// The drop counters register themselves during derpserver package
	// initialization; only the per-server set has to be published here.
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

var (
	// trackedCounters is the compared subset of server counters, named as Go's
	// varz exposes them.
	trackedCounters = buildTrackedCounters()
	// droppedCounters is every packets_dropped reason/kind cell.
	droppedCounters = buildDroppedCounters()
	// queuePressure names the counters whose magnitude under a stalled
	// recipient depends on kernel socket buffer sizes.
	queuePressure = buildQueuePressure()
)

func buildQueuePressure() []string {
	names := append([]string{"derp_packets_sent"}, buildDroppedCounters()...)
	sort.Strings(names)
	return names
}

func buildDroppedCounters() []string {
	reasons := []string{
		"dup_client",
		"gone_disconnected",
		"queue_head",
		"queue_tail",
		"unknown_dest",
		"unknown_dest_on_fwd",
		"write_error",
	}
	names := []string{}
	for _, kind := range []string{"disco", "other"} {
		for _, reason := range reasons {
			names = append(names,
				fmt.Sprintf("derp_packets_dropped{kind=%q,reason=%q}", kind, reason))
		}
	}
	sort.Strings(names)
	return names
}

func buildTrackedCounters() []string {
	names := []string{
		"derp_current_connections",
		"derp_current_dup_client_conns",
		"derp_current_dup_client_keys",
		"derp_got_ping",
		"derp_packets_forwarded_in",
		"derp_packets_received",
		"derp_packets_sent",
		"derp_peer_gone_disconnected_frames",
		"derp_peer_gone_not_here_frames",
		"derp_sent_pong",
		"derp_total_dup_client_conns",
		"derp_unknown_frames",
	}
	names = append(names, buildDroppedCounters()...)
	sort.Strings(names)
	return names
}

type collector struct {
	url      string
	token    string
	client   *http.Client
	base     int64
	previous map[string]int64
}

func newCollector(url, token string) *collector {
	collector := &collector{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: scrapeTimeout},
	}
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

	response, err := c.client.Do(request)
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

// step snapshots the tracked counters and returns both the trace record, whose
// saturating counters are reduced to their sign, and the raw deltas.
func (c *collector) step(
	name string,
	saturating []string,
	connections int64,
	events []traceEvent,
) (stepTrace, map[string]int64) {
	values := c.settle(connections)
	saturated := make(map[string]bool, len(saturating))
	for _, metric := range saturating {
		saturated[metric] = true
	}

	raw := make(map[string]int64, len(trackedCounters))
	counters := make(map[string]int64, len(trackedCounters))
	for _, metric := range trackedCounters {
		delta := values[metric] - c.previous[metric]
		raw[metric] = delta
		if saturated[metric] {
			delta = sign(delta)
		}
		counters[metric] = delta
	}
	c.previous = values

	if os.Getenv("DERPEX_TRACE_RAW") != "" {
		encoded, err := json.Marshal(raw)
		must(err)
		fmt.Fprintf(os.Stderr, "DERPEX_TRACE_RAW %s %s\n", name, encoded)
	}

	if events == nil {
		events = []traceEvent{}
	}
	if saturating == nil {
		saturating = []string{}
	}
	return stepTrace{
		Step:       name,
		Saturating: saturating,
		Events:     events,
		Counters:   counters,
	}, raw
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
	raw         map[string]map[string]int64
	collector   *collector
	connections int64
}

// step round-trips a ping on every named client before snapshotting. A DERP
// server reads one connection's frames in order and drains its pong last, so a
// received pong proves both that the frames that client sent have been routed
// and that the frames queued for it have been written and counted.
func (r *runner) step(
	name string,
	saturating []string,
	barriers []*derphttp.Client,
	events []traceEvent,
) stepTrace {
	for _, client := range barriers {
		pingPong(client, [8]byte{0x9b, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72})
	}

	step, raw := r.collector.step(name, saturating, r.connections, events)
	r.raw[name] = raw
	return step
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

// unknownPeer mints a key that never connects, under a stable trace label.
func (r *runner) unknownPeer(label string) key.NodePublic {
	peer := key.NewNode().Public()
	r.labels[peer] = label
	return peer
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

// relayAndDrops relays packets, answers a ping, reports unknown destinations of
// both packet kinds, and then overruns a recipient that has stopped reading.
func relayAndDrops(r *runner) scenarioTrace {
	scenario := scenarioTrace{Name: "relay_and_drops"}

	first, firstInfo := r.connect("first", "", key.NewNode(), key.DERPMesh{}, false)
	second, secondInfo := r.connect("second", "", key.NewNode(), key.DERPMesh{}, false)
	stalled, stalledInfo := r.connect("stalled", "", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("connect_clients", nil, nil,
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
	scenario.add(r.step("relay_payloads", nil, clients(second), relayed))

	pong := pingPong(first, [8]byte{0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47})
	digest := sha256.Sum256(pong[:])
	scenario.add(r.step("ping_pong", nil, nil, []traceEvent{{
		Kind:   "pong",
		Client: "first",
		Size:   len(pong),
		SHA256: hex.EncodeToString(digest[:]),
	}}))

	// A disco packet to a key nobody holds is dropped and answered with a
	// not-here frame; a plain packet to one is dropped silently.
	discoUnknown := r.unknownPeer("unknown_disco")
	must(second.Send(discoUnknown, discoPayload(discoUnknown, 0)))
	scenario.add(r.step("unknown_destination_disco", nil, clients(second), []traceEvent{
		r.peerGoneEvent("second", requirePeerGone(recvTimeout(second), discoUnknown)),
	}))

	plainUnknown := r.unknownPeer("unknown_plain")
	must(first.Send(plainUnknown, []byte("plain packet to nobody")))
	scenario.add(r.step("unknown_destination_plain", nil, clients(first), nil))

	// The stalled client never reads. The ordinary flood fills its socket
	// buffers and then overruns the ordinary send queue; with the writer stuck
	// on that queue, the disco flood overruns the separate disco queue.
	ordinaryFlood := bytes.Repeat([]byte{0x5a}, derp.MaxPacketSize)
	discoFlood := discoPayload(stalled.SelfPublicKey(), derp.MaxPacketSize)
	for range ordinaryFloodPackets {
		must(second.Send(stalled.SelfPublicKey(), ordinaryFlood))
	}
	for range discoFloodPackets {
		must(second.Send(stalled.SelfPublicKey(), discoFlood))
	}
	scenario.add(r.step("flood_stalled_recipient", queuePressure, clients(second), nil))

	// Once the recipient reads again, the writer hands over exactly what the
	// two 32-deep send queues plus the one packet in flight still hold, so this
	// step pins the send-queue depth exactly; only the drop cells stay signed.
	drain(stalled)
	r.close(stalled)
	scenario.add(r.step("drain_stalled_recipient", droppedCounters, nil, nil))
	assertConservation(r, "flood_stalled_recipient", "drain_stalled_recipient")

	firstPublic := first.SelfPublicKey()
	r.close(first)
	goneFirst := r.peerGoneEvent("second", requirePeerGone(recvTimeout(second), firstPublic))
	scenario.add(r.step("close_first", nil, clients(second), []traceEvent{goneFirst}))

	r.close(second)
	scenario.add(r.step("close_second", nil, nil, nil))
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
	scenario.add(r.step("connect_duplicates", nil, nil,
		[]traceEvent{olderInfo, newerInfo, senderInfo}))

	newestPayload := []byte("newest duplicate")
	must(sender.Send(duplicate.Public(), newestPayload))
	newestEvent := r.packetEvent("newer",
		requirePacket(recvTimeout(newer), sender.SelfPublicKey(), newestPayload))
	scenario.add(r.step("newest_connection_receives", nil, clients(newer),
		[]traceEvent{newestEvent}))

	olderPayload := []byte("older active")
	must(older.Send(sender.SelfPublicKey(), olderPayload))
	olderEvent := r.packetEvent("sender",
		requirePacket(recvTimeout(sender), duplicate.Public(), olderPayload))
	scenario.add(r.step("older_connection_writes", nil, clients(sender),
		[]traceEvent{olderEvent}))

	lastPayload := []byte("last writer")
	must(sender.Send(duplicate.Public(), lastPayload))
	lastEvent := r.packetEvent("older",
		requirePacket(recvTimeout(older), sender.SelfPublicKey(), lastPayload))
	scenario.add(r.step("last_writer_receives", nil, clients(older),
		[]traceEvent{lastEvent}))

	r.close(older)
	r.close(newer)
	goneDuplicate := r.peerGoneEvent("sender",
		requirePeerGone(recvTimeout(sender), duplicate.Public()))
	scenario.add(r.step("close_duplicate_connections", nil, clients(sender),
		[]traceEvent{goneDuplicate}))

	r.close(sender)
	return scenario
}

// watchPresence drives a trusted mesh watcher over the presence snapshot, a
// forwarded packet for a destination this server does not hold, a later
// arrival, and a departure.
func watchPresence(r *runner) scenarioTrace {
	scenario := scenarioTrace{Name: "watch_presence"}

	alpha, alphaInfo := r.connect("alpha", "alpha-app", key.NewNode(), key.DERPMesh{}, false)
	scenario.add(r.step("connect_regular", nil, nil, []traceEvent{alphaInfo}))

	watcher, watcherInfo := r.connect("watcher", "", key.NewNode(), r.meshKey, true)
	snapshot := []traceEvent{}
	for range 2 {
		snapshot = append(snapshot,
			r.presenceEvent("watcher", requirePresent(recvTimeout(watcher))))
	}
	// The initial snapshot enumerates connected peers in unspecified order.
	sortEvents(snapshot)
	scenario.add(r.step("connect_watcher", nil, clients(watcher),
		append([]traceEvent{watcherInfo}, snapshot...)))

	// A mesh peer may forward for a key this server does not hold. As on the
	// local send path, only the disco packet earns a not-here reply.
	plainForward := r.unknownPeer("unknown_forward_plain")
	must(watcher.ForwardPacket(alpha.SelfPublicKey(), plainForward, []byte("forwarded nowhere")))
	discoForward := r.unknownPeer("unknown_forward_disco")
	must(watcher.ForwardPacket(
		alpha.SelfPublicKey(), discoForward, discoPayload(discoForward, 0)))
	goneForward := r.peerGoneEvent("watcher",
		requirePeerGone(recvTimeout(watcher), discoForward))
	scenario.add(r.step("forward_unknown_destination", nil, clients(watcher),
		[]traceEvent{goneForward}))

	beta, betaInfo := r.connect("beta", "beta-app", key.NewNode(), key.DERPMesh{}, false)
	betaPresence := r.presenceEvent("watcher", requirePresent(recvTimeout(watcher)))
	scenario.add(r.step("present_second_regular", nil, clients(watcher),
		[]traceEvent{betaInfo, betaPresence}))

	betaPublic := beta.SelfPublicKey()
	r.close(beta)
	goneBeta := r.peerGoneEvent("watcher", requirePeerGone(recvTimeout(watcher), betaPublic))
	scenario.add(r.step("close_second_regular", nil, clients(watcher),
		[]traceEvent{goneBeta}))

	r.close(watcher)
	r.close(alpha)
	return scenario
}

// assertConservation checks each server against itself: every packet the server
// accepted while the recipient was stalled was either written to that recipient
// or dropped for a recorded reason, with nothing left over once the recipient
// has caught up and disconnected.
func assertConservation(r *runner, floodStep, drainStep string) {
	flood, drain := r.raw[floodStep], r.raw[drainStep]
	sent := flood["derp_packets_sent"] + drain["derp_packets_sent"]

	dropped := int64(0)
	for _, metric := range droppedCounters {
		dropped += flood[metric] + drain[metric]
	}

	received := flood["derp_packets_received"]
	if received != sent+dropped {
		fail("conservation: received %d != sent %d + dropped %d", received, sent, dropped)
	}
}

func (s *scenarioTrace) add(step stepTrace) {
	s.Steps = append(s.Steps, step)
}

func clients(values ...*derphttp.Client) []*derphttp.Client { return values }

func sortEvents(events []traceEvent) {
	sort.Slice(events, func(i, j int) bool {
		left, err := json.Marshal(events[i])
		must(err)
		right, err := json.Marshal(events[j])
		must(err)
		return string(left) < string(right)
	})
}

// discoPayload builds a packet both servers classify as disco, padded to size.
func discoPayload(source key.NodePublic, size int) []byte {
	payload := source.AppendTo([]byte(disco.Magic))
	payload = append(payload, make([]byte, disco.NonceLen)...)
	if size > len(payload) {
		payload = append(payload, bytes.Repeat([]byte{0x5a}, size-len(payload))...)
	}
	return payload
}

func pingPong(client *derphttp.Client, data [8]byte) derp.PongMessage {
	must(client.SendPing(data))
	pong, ok := recvTimeout(client).(derp.PongMessage)
	if !ok || pong != derp.PongMessage(data) {
		fail("ping was not answered with the same pong payload")
	}
	return pong
}

// drain lets a stalled recipient catch up so its send queues are empty before
// it disconnects, keeping the shutdown path free of queue-pressure drops.
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
