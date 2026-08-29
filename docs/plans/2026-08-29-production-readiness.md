# DERPEX Production Readiness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (fresh subagent per task, review between tasks). Every task: failing test first, minimal fix, `mix quality` green, commit.

**Goal:** Close every blocker and should-fix from the 2026-08-29 five-way review so DERPEX can run on a public :443 as Gentility's production relay.

**Architecture:** No redesign. Fixes cluster into: ship hygiene (A), outbox ring/writer (B), router (C), mesh client (D), Gentility admission (E), certificates (F), test honesty (G), ops hardening (H). Clusters are sequenced so each leaves `mix quality` and the Go interop gates green. Mesh (C+D) is the only cluster needing design work: an unbounded-with-coalesced-wake lifecycle queue and region-aware presence.

**Tech Stack:** Elixir 1.20 / OTP 29, Thousand Island, Rustler (crypto only), StreamData (to add), Go 1.27 pinned oracle at `../tailscale`.

**Ground rules for every task**
- Read PLAN.md §3.3, §3.5, §8 and docs/adr/0001 before touching lib/derpex/outbox or writer.
- Go reference for any behavior question: `../tailscale/derp/derpserver/derpserver.go`. Pinned Go wins.
- Run `DERPEX_BUILD=1 MIX_ENV=test mix quality` before every commit. Run the Go interop gate (`DERPEX_TAILSCALE_DIR=../tailscale DERPEX_GO_INTEROP=1 mix test test/interop/go_client_test.exs test/interop/differential_test.exs`) at the end of every cluster.
- Commit per task. Message: imperative summary line, body says which review finding it closes (e.g. `Closes review B1`).
- Never `pkill`; never touch processes you didn't start.

---

## Cluster A — ship hygiene (do first, all small)

### A1: Redact private keys from process state
**Files:** `lib/derpex/connection.ex:22`, `lib/derpex/session.ex:16`, `lib/derpex/application.ex:98,159`, `lib/derpex/listener_supervisor.ex`; tests `test/derpex/connection_test.exs`, `test/derpex/session_test.exs`.
**Behavior:** `inspect(%Connection{})`, `inspect(%Session{})` and any crash-report `State:` line must not contain the server private key or mesh key bytes. Move `server_private_key` into a zero-arity closure or `:persistent_term` keyed by listener; keep only a reference in state. `@derive {Inspect, except: [...]}` on both structs as belt-and-braces. Child spec args must carry a key *reference*, not the key.
**Failing test:** generate a key, build state, assert `refute inspect(state, limit: :infinity) =~ Base.encode16(key)`; also spawn a GenServer holding the state, crash it with `Logger` captured, assert log excludes the key hex.
**Acceptance:** `grep -rn server_private_key lib/ | grep -v 'defp\|@spec\|persistent_term'` shows no struct field storage.

### A2: Make the release actually gated
**Files:** `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `mix.exs:55-78`, `test/test_helper.exs`, `README.md`, `PLAN.md` §5.3.
**Behavior:** `mix test.all` runs unit + interop + differential + rust + tsnet (sets the env tags itself via `--include`); `mix quality` no longer runs `test` (fast pre-commit gate: format, compile, credo, clippy, fmt); `mix release.check` = quality + test.all + artifact.check. `release.yml` gains a `gate` job that `needs:` nothing but runs the full CI workflow steps (or `workflow_call` to ci.yml) and every publish job `needs: gate`. Add `mix test.system` alias (§5.3) running `test/system/**` (create dir with the SIGHUP test from G7 later; alias can exist empty).
**Acceptance:** `grep -n needs .github/workflows/release.yml` shows every publish job depends on the gate; `mix test.all` locally runs 271+ tests with `DERPEX_TAILSCALE_DIR`/`DERPEX_TAILSCALE_RS_DIR` set.

### A3: Dirty-schedule the NaCl NIFs and cap pre-auth client info
**Files:** `native/derpex_crypto/src/lib.rs:25,51`, `lib/derpex/connection.ex:235-246`, `test/derpex/crypto/native_test.exs`, `test/derpex/connection_test.exs`, `native/derpex_crypto/src/lib.rs` (add `#[cfg(test)]` unit tests — the crate currently has zero).
**Behavior:** `open`/`seal` get `#[rustler::nif(schedule = "DirtyCpu")]`. `@max_client_info_length` drops from 256 KiB to 16 KiB (Go's `MaxInfoLen` is 1 MiB but real ClientInfo < 200 B; document the exception in PLAN §2.3 since Go accepts up to 1 MiB — check `derpserver.go` `recvClientKey` for the actual bound and match it if it is smaller). Add Rust unit tests for: short nonce, wrong key length, tampered ciphertext, round trip.
**Acceptance:** `cargo test` reports ≥4 tests; connection test rejects a 17 KiB client-info frame with the same close phase Go uses for oversize.

### A4: Scope the HTTP header-terminator scan
**Files:** `lib/derpex/http1/parser.ex:37-39`, same pattern in `lib/derpex/http_client.ex:143-160,290-307,330-346` and `lib/derpex/mesh/client.ex` `receive_http_upgrade`; tests `test/derpex/http1/parser_test.exs`.
**Behavior:** `:binary.match(buffer, "\r\n\r\n", scope: {max(0, byte_size(old) - 3), ...})`. Failing test: push a 400 KB header 1 byte at a time; assert wall time < 200 ms (use `:timer.tc`; current is ~2.4 s).
**Acceptance:** test passes; max_header_bytes still enforced.

### A5: Create key files 0600 from birth
**Files:** `lib/derpex/atomic_file.ex:12-26`, `lib/derpex/identity.ex:101-122`, `lib/derpex/certificates/ip_manager.ex:199-202`, `lib/derpex/certificates/manual.ex:118-120`; tests `test/derpex/identity_test.exs`, `test/derpex/certificates/manual_test.exs`.
**Behavior:** create the parent directory `0700`; open with `:file.open(path, [:write, :exclusive, :raw, :binary])` **after** `File.chmod` is impossible — so instead create via `:file.open/2` then immediately chmod *before any write*, AND ensure directory is 0700 so the window is unobservable. Route the two `File.write` call sites through `AtomicFile.write/3`. Add directory `fsync` after rename (open dir, `:file.sync`, close).
**Failing test:** stat the directory after `load_or_create` → mode `0o700`; stat key → `0o600`; ip_manager and manual key writes go through AtomicFile (assert temporary file never left behind).

### A6: Serve rotated certificates to no-SNI clients
**Files:** `lib/derpex/listener_supervisor.ex:120-142`, `lib/derpex/certificates/reloader.ex:18-29`; test `test/derpex/certificates/reloader_test.exs`.
**Behavior:** after a reload, a client connecting with no `server_name` gets the new cert. Simplest: `sni_fun` is only for SNI; for the default, use `:ssl.handshake_continue` with `handshake: :hello` in Thousand Island transport options and select certs_keys from the snapshot in both paths — or, if TI doesn't expose that, restart the acceptor pool's listen options via `ThousandIsland.suspend/resume` on reload. Pick the approach that keeps existing connections alive; document in the module doc.
**Failing test:** start TLS listener, rotate cert, `:ssl.connect` with `server_name_indication: :disable`, assert peer cert serial == new.

### A7: Rust interop test uses absolute upstream path
**Files:** `test/interop/rust_client_test.exs:16,91`.
**Behavior:** `Path.expand(System.get_env(...))`. Verify: `DERPEX_TAILSCALE_RS_DIR=../tailscale-rs DERPEX_RUST_INTEROP=1 mix test test/interop/rust_client_test.exs` passes from repo root.

### A8: Reject HTTP/1.1 without Host; exact WebSocket subprotocol
**Files:** `lib/derpex/http1/parser.ex:59`, `lib/derpex/http1.ex:290-300`; tests `test/derpex/http1_test.exs`.
**Behavior:** HTTP/1.1 request with no `Host` → 400 (match Go `net/http`). Split `Sec-WebSocket-Protocol` on `,`, trim, exact-match `derp`; otherwise respond as Go's `websocket.Accept` does when no subprotocol matches (read `../tailscale/derp/derpserver/websocket.go:40-60` and the coder/websocket behavior: it accepts with no subprotocol then DERPEX must close with policy violation 1008). Tests for `notderp`, `derp2`, `foo, derp`.

### A9: Reject wrong first frame on header, not after body
**Files:** `lib/derpex/connection.ex:235`, `lib/derpex/frame/decoder.ex:98`; test `test/derpex/connection_test.exs`.
**Behavior:** in `:handshake` phase, a header whose type ≠ `client_info` closes immediately (Go `recvClientKey`: `if fl != frameClientInfo { return ..., fmt.Errorf("unexpected frame type") }`). Test: send `<<0xFF, 0xFFFFFFFF::32>>` and assert close within 100 ms, not at the 10 s deadline.

### A10: AcceptLimiter degrades to allow when tracking table is full
**Files:** `lib/derpex/accept_limiter.ex:174-184,250-254`; test `test/derpex/accept_limiter_test.exs`.
**Behavior:** when `max_tracked_ips` is reached by IPs holding live connections, a new IP is admitted untracked and a `derpex_accept_limiter_untracked_total` counter increments; never `{:error, :ip_tracking_limited}` for a new IP. Test with `max_tracked_ips: 2`, three IPs each holding a connection → third admitted.

### A11: Rate-limit the admission-unavailable warning; sanitize reloader log
**Files:** `lib/derpex/http_admission.ex:134`, `lib/derpex/certificates/reloader.ex:96,137-141`.
**Behavior:** warning at most once per 30 s (use `Logger` metadata + an `:atomics` timestamp; no process). Reloader logs a fixed reason atom (`:invalid_private_key`, `:missing_file`, …) never `inspect(reason)` from a `rescue`. Test: capture_log on 100 failed admissions → 1 warning; malformed key file → log has no `<<` byte sequences.

### A12: Debug CGNAT grant opt-in
**Files:** `lib/derpex/debug/access.ex:97-101`, `config/runtime.exs`, README.
**Behavior:** `DERPEX_DEBUG_ALLOW_TAILSCALE_CGNAT=1` enables the 100.64/10 rule; default off. Test both.

**Cluster A gate:** `mix quality`, Go interop, Rust interop all green. Commit tag-free.

---

## Cluster B — outbox ring and writer

### B1: Ring producers make a single lock attempt (ADR 0001)
**Files:** `lib/derpex/outbox/ring.ex:297-326`, `test/derpex/outbox/ring_test.exs:83-116`, `docs/adr/0001-bounded-outbox-ring.md`.
**Behavior:** delete `acquire_producer_wait`, `@producer_waiters`, `@producer_wait_attempts`; `acquire_producer` = `try_acquire`; `acquire_consumer` = `try_acquire`. Contention → `{:dropped, :tail}` (existing tail-drop path). Rewrite the contention test to assert: no producer ever sleeps (measure max enqueue latency < 1 ms under 8 concurrent producers), `head_drops + tail_drops + delivered == sent`, and tail drops are a small fraction. Update ADR "Consequences" to state tail drops are expected under contention and are counted.
**Failing test first:** a producer killed mid-enqueue (use `Process.exit(pid, :kill)` while it's inside `Ring.enqueue` in a loop) must not make a later `take` return `:busy` more than once. (This is the B1-reviewer repro; it fails today.)

### B2: Writer never self-spins on `:busy`
**Files:** `lib/derpex/writer.ex:95-130`.
**Behavior:** on `:busy`, do **not** `send(self(), wake)`. The lock holder is a producer that will signal the wake flag on publish (ring guarantees wake-after-publish under lock), so simply return. Add a 5 ms `Process.send_after` safety wake only if `wake_pending` is already clear (guard against the latent lost-wakeup at `writer.ex:102`: clear `wake_pending` correctly when `rings: nil`).
**Test:** stall the transport, enqueue while holding the lock from a test process, assert writer `reductions` delta over 100 ms < 10_000.

### B3: Fair ring selection
**Files:** `lib/derpex/writer.ex:136-154`; test `test/derpex/writer_test.exs`.
**Behavior:** lifecycle first (Go sends mesh updates/peer-gone preferentially — confirm at `derpserver.go:2040-2100` `sendLoop` select; Go's select is random among ready). Implement: lifecycle if nonempty, else round-robin among ordinary/disco/pong by age (`take_with_age` returns age — pick the oldest ready head). Test: saturate ordinary, enqueue one pong and one disco; assert both are written within N ordinary frames (N = 2).

### B4: Control write timeout ≥ socket write timeout
**Files:** `lib/derpex/writer.ex:31-34`, `lib/derpex/listener/handler.ex:321,355-359`.
**Behavior:** `write_control/3` default timeout = the connection's configured send timeout + 1000 ms; handler passes the mesh (30 s) or regular (2 s) value. Test: writer with a transport that sleeps 6 s, mesh timeout → call succeeds.

### B5: server_info always precedes queued packets
**Files:** `lib/derpex/listener/handler.ex:320-368,706`, `lib/derpex/connection.ex:6-8,208-213`; tests `test/derpex/listener/handler_test.exs`, new Go-interop scenario in `interop/go/protocol_edges.go`.
**Behavior:** write `server_info` through the Writer **before** `Router.register` publishes rings (Go: `sendServerInfo` then `c.run`). Update the moduledoc. Test: two clients; B registers while a flood from A to B's key is in flight (A sends before B's server_info is written — use a Router hook or `:erlang.trace`); assert B's first frame is `server_info`. Also make `Mesh.Client`'s strictness (`mesh/client.ex:243-245`) pass against DERPEX in the interop mesh test under load.

### B6: Drop `write_concurrency` from ring tables; measure per-connection memory
**Files:** `lib/derpex/outbox/ring.ex:54-60`; `bench/relay.exs` add idle-memory-per-connection sample.
**Behavior:** `read_concurrency: false, write_concurrency: false` (all access is under the ring lock). Test: `:ets.info(t, :memory)` for a 32-slot ring < 4 KB words. Bench prints bytes/idle connection.

### B7: Count post-teardown drops and mesh-ring drops
**Files:** `lib/derpex/router.ex:665-669`, `lib/derpex/listener/handler.ex:511-516`, `lib/derpex/mesh/client.ex:405`, `lib/derpex/metrics.ex`.
**Behavior:** `{:dropped, :closed_destination}` increments `gone_disconnected`; mesh forwarding ring is created with `metrics:`/`metric_kind: :forward`. Tests assert counter deltas.

### B8: `note_send` once per (dst, src)
**Files:** `lib/derpex/writer.ex:156-161`, `lib/derpex/router.ex:160`.
**Behavior:** Writer keeps a `MapSet` of sources already noted (bounded — it's ≤ number of distinct senders; Go's `sawSrc` is the same shape); calls `Router.note_send` only on first sight. Reverse-table row stores `{lifecycle_ref}` not the whole `%Ring{}`. Test: 1000 packets from one source → exactly one ETS insert (use `:ets.info(size)`).

### B9: Non-blocking receive pacing
**Files:** `lib/derpex/listener/handler.ex:780-800`, `test/derpex/listener/handler_test.exs:257`.
**Behavior:** replace the selective `receive` with handler state `{:paced_until, timer_ref, pending_frame}`; return `{:noreply}` with the socket passive, resume on the timer message via normal `handle_info` so keepalive ticks, rate updates, and `:derpex_drain_close` are processed while paced. Test: at 1 byte/s, send a max frame, then send a drain close → connection closes within 100 ms; keepalive still emitted while paced (manual clock).

### B10: Per-transport write-timeout tests (TCP, TLS, WebSocket)
**Files:** new `test/derpex/writer_timeout_test.exs`; `lib/derpex/listener/transports/ssl.ex` (explicit `:timer`-wrapped `:ssl.send` so it doesn't depend on OTP's transitional `tls_sender` clause); `lib/derpex/writer.ex:196-209` (WebSocket: one send per frame using iodata, no 16 KB chunk loop resetting the budget; no `iodata_to_binary`).
**Test:** for each transport start a real listener, connect a client that never reads, fill the kernel buffers, assert the *server* closes that connection within `timeout + 500 ms` and a second client on the same listener keeps relaying throughout.

**Cluster B gate:** `mix quality`, Go interop, and `mix bench -- --packets 2000` runs. Commit.

---

## Cluster C — router

### C1: O(1) reverse-path cleanup
**Files:** `lib/derpex/router.ex:160,614-626`; test `test/derpex/router_test.exs`.
**Behavior:** replace the single compound-key `:set` with two tables: `@reverse_by_source` (`bag`, key = source, value = connection) and `@reverse_by_connection` (`bag`, key = connection, value = source) — or one `duplicate_bag` each way. `forget_destination(conn)` = lookup by connection, delete matching rows in both, O(k). `notify_peer_gone(key)` = lookup by source. Test: 2000 connections × 100 sources; `forget_destination` < 1 ms (`:timer.tc`).

### C2: Region-aware PeerGone
**Files:** `lib/derpex/router.ex:398-430,452-480,558-580`; test `test/derpex/router_test.exs`; Go reference `derpserver.go` `unregisterClient` → `notePeerGoneFromRegion` and `removePeerGoneFromRegionWatcher` / forwarder removal.
**Behavior:** `PeerGone(Disconnected)` fires only when after removal the key has **neither** a local route nor a forwarder. Removing the last forwarder with no local route → fires. Removing the last local route while a forwarder remains → does not fire. Reverse-path rows are cleaned in both fire cases. Tests for all four transitions.

### C3: Unbounded lifecycle queue with coalesced wake
**Files:** new `lib/derpex/outbox/lifecycle_queue.ex`; `lib/derpex/listener/handler.ex:86-90`; `lib/derpex/router.ex:345-352,657-663`; `lib/derpex/writer.ex`; ADR `docs/adr/0003-lifecycle-queue.md`; tests `test/derpex/outbox/lifecycle_queue_test.exs`, `test/derpex/router_test.exs`, Go interop watch scenario extended to 100 peers.
**Behavior:** match Go — retain every `peer_present`/`peer_gone` state change; coalesce only the wakeup. Design: per-watcher ETS `ordered_set` keyed by monotonic sequence, same lock/wake-flag protocol as `Ring` (reuse the lock helpers — extract them into `Derpex.Outbox.Lock` if needed), no capacity cap but a `size` atomic exposed as a gauge and a per-watcher **soft** cap (default 65_536 entries) beyond which the *watcher connection* is closed with a logged reason — Go's slice is unbounded; closing a hopeless watcher is the safe BEAM analogue and must be documented in the ADR and PLAN §2.3 as an exception. Compaction: a `peer_gone` for a key with a not-yet-sent `peer_present` may cancel both (Go does not compact — skip this; YAGNI). Writer drains lifecycle queue first (B3).
**Failing test:** 100 registered peers, one watcher with a stalled writer → after unstalling, watcher receives exactly 100 `peer_present`. Go interop: `interop/go/watch_smoke.go` extended to 3 watchers, 100 clients, late joiner sees full snapshot (mirrors `TestWatch` derp_test.go:875).

### C4: `note_activity` atomic short-circuit
**Files:** `lib/derpex/router.ex:169`. Keep a per-connection `is_dup` atomics flag set by the router on dup transitions; handler checks it before the ETS lookup. Test: single (non-dup) connection sending 10k frames performs zero `note_activity` ETS lookups (count via `:ets.info` access or a test hook).

**Cluster C gate:** Go interop incl. extended watch scenario. Commit.

---

## Cluster D — mesh client

### D1: Send timeout on outbound mesh sockets (5 s, Go `ForwardPacket`)
**Files:** `lib/derpex/mesh/client.ex:417-440,527-538,662-663`; test `test/derpex/mesh/client_test.exs`.
**Behavior:** `send_timeout: 5_000, send_timeout_close: true` on TCP; explicit timer around `:ssl.send` (share the helper from B10). A send timeout → `disconnect_and_retry`. Test: peer stops reading; mesh client reconnects within 6 s.

### D2: Receive deadline / keepalive watchdog (120 s)
**Files:** `lib/derpex/mesh/client.ex:137-170,260-270`.
**Behavior:** after each received frame reset a `Clock.send_after(self(), :recv_deadline, 120_000)`; on fire → withdraw all forwarders learned from this peer and `disconnect_and_retry`. Test with `ManualClock`: no frames for 120 s → forwarders removed, reconnect attempted.

### D3: Non-recursive forwarded-packet drain
**Files:** `lib/derpex/mesh/client.ex:323-341`.
**Behavior:** drain at most 64 packets per wake, then `send(self(), @wake_message)` if more remain, so socket data, `PeerGone`, timers and calls interleave. Test: sustained producer + a `:tcp_closed` message → close handled within 50 ms.

### D4: Ring tables are deleted on mesh reconnect
**Files:** `lib/derpex/outbox/ring.ex:126-147` (add `Ring.delete/1`), `lib/derpex/mesh/client.ex:343-357`.
**Test:** 100 reconnects → `length(:ets.all())` delta == 0.

**Cluster D gate:** Go interop mesh scenarios; add a 3-node mesh failure/convergence interop scenario if `interop/go/mesh_control_smoke.go` lacks one. Commit.

---

## Cluster E — Gentility admission

### E1: Any authority error falls back to cache
**Files:** `lib/derpex/admission/gentility.ex:385-402`, `lib/derpex/admission/gentility/control_plane.ex:13`, `docs/adr/0002-gentility-contract-v1.md`.
**Behavior:** `{:error, _}` from the authority → `{:cached, node_key}`. A *deny* must arrive as a signed record, never an error tuple. Update the behaviour spec/docs. Test: authority returns `{:error, {:http, 503}}` → cached lease admits.

### E2: Lease cache: configurable, expiry-ordered, never evicts live claims
**Files:** `lib/derpex/admission/gentility.ex:24,474,951-963`, `config/runtime.exs`, docs.
**Behavior:** `DERPEX_GENTILITY_MAX_CACHE_ENTRIES` (default 100_000), plus env for `max_lease_ms`, `max_future_skew_ms`, `max_revocations`, `max_concurrent_requests`, `authority_timeout`, `max_byte_delay_ms`. Eviction order: expired first, then soonest-expiring **among entries with zero active claims**; if every entry has a live claim, reject the *new* admission with `:cache_full` (counted) rather than closing an established peer. Tests for each rule.

### E3: Usage windows never brick the relay
**Files:** `lib/derpex/admission/gentility/usage.ex:42-61`, `usage_worker.ex:228-242`, `usage_contract.ex:11`.
**Behavior:** `oldest_closed` yields batches of ≤ `@max_entries`; a window with more rows produces several batches. An un-encodable batch is logged, counted (`derpex_gentility_usage_dropped_rows`), and its rows deleted — never a permanent block. Test: 10_001 identities in one window → two batches spooled, no `blocked`.

### E4: Incremental budgets
**Files:** `lib/derpex/admission/gentility.ex:704-836`; extract to `lib/derpex/admission/gentility/budgets.ex`.
**Behavior:** claim/release touch only the two affected budget entries; ETS prune on a timer (30 s), not per call. `over_limit_connections` only runs on lease *revision* changes. Test: 10_000 claims; `claim` p99 < 100 µs (`:timer.tc`).

### E5: Lease renewal and jittered expiry
**Files:** `lib/derpex/admission/gentility.ex:893-923`, `authority.ex`.
**Behavior:** at 80 % of lease lifetime, re-authorize in the background (bounded concurrency via existing `max_concurrent_requests`); success replaces the lease without closing; failure → keep serving until expiry; at expiry close with jitter ±10 % spread. Test with ManualClock.

### E6: Logging and metrics for lease state
**Files:** `lib/derpex/admission/gentility.ex`, `events.ex`, `usage_worker.ex`, `lib/derpex/operations.ex:306-321`.
**Behavior:** `Logger.warning` (rate-limited) on: authority unavailable → serving cached; revocation applied (count); spool full; eviction; key rotation; cache load/persist errors. Metrics: `authorize_total{outcome=live|cached|denied,reason}`, `close_peer_total{cause}`, `nearest_lease_expiry_seconds`, `cache_load_error`/`persist_error` gauges. Test: capture_log + metrics snapshot.

### E7: Spool-full sheds cleanly
**Files:** `lib/derpex/listener/handler.ex:298-299,444,557-558,764-766`.
**Behavior:** `{:usage, _}` and `{:rate_limit, :usage_spool_full}` map to a clean `{:stop, :normal}` with a counted drop, not a crash report. Test: capture_log shows no crash report.

### E8: Org byte budget paces siblings, doesn't close them
**Files:** `lib/derpex/admission/gentility.ex:131-135`, `byte_budget.ex:86-96`.
**Behavior:** org debt → pacing delay only; connection close only on *per-node* debt exceeding `max_byte_delay_ms`. Test: noisy node A, quiet node B same org → B remains connected.

### E9: Reconciliation paging + revocation bound documented
**Files:** `control_plane.ex`, `gentility.ex:567-576`, `events.ex:216-233`, ADR 0002.
**Behavior:** `reconcile/1` returns `{:ok, revocations, cursor | nil}`; controller pages until nil. Document that Gentility prunes revocations older than `max_lease_ms`. Test: 25_000 revocations across 3 pages → stream mode reached.

### E10: Region check + unguarded nil + sequential close_peer
**Files:** `gentility.ex:594,663-664,810,816,965-968`.
**Behavior:** lease `region_id` ≠ configured → deny `:wrong_region`; `Map.fetch` with default for budgets; mass closes run via `Task.async_stream` outside the controller's `handle_call` (cast to a closer). Tests.

### E11: Lease TTL and outage semantics documented
**Files:** `docs/deployment/gentility.md`, README, PLAN §3.6.
**Content:** worst-case revoked-node window = `max_lease_ms` (15 min); Gentility outage > one TTL darkens the relay (with E5, > TTL from last successful renewal); recommended alert on `nearest_lease_expiry_seconds`; per-instance budgets must be divided by instance count.

**Cluster E gate:** `mix test test/derpex/admission` + full quality. Commit.

---

## Cluster F — certificates

### F1: Wire certificate modes into the runtime, honestly
**Files:** `lib/derpex/application.ex:53`, `lib/derpex/listener_supervisor.ex:120`, `lib/derpex/certificates/mode.ex`, `config/runtime.exs`, `interop/COVERAGE.md` via `scripts/upstream_inventory.exs`, PLAN §2.3.
**Behavior:** `DERPEX_CERT_MODE=manual` (default) works as today. `letsencrypt`/`gcp` are **rejected at boot with a clear error** until an ACME client exists (F3). `IPManager` is wired for manual-issuer use behind `DERPEX_IP_CERT_ISSUER=self` only. COVERAGE: `TestIPCertManager`, `TestIPCertManagerNextProvider`, and every cert row that depends on ACME → `pending`. PLAN §2.3 records ACME as pending, not deferred.

### F2: IPManager validity checks
**Files:** `lib/derpex/certificates/ip_manager.ex:133,172`.
**Behavior:** reject `NotBefore`/`NotAfter` outside now; renew at 2/3 lifetime. Tests with ManualClock.

### F3: ACME client (RFC 8555) — last stable-surface task
**Files:** new `lib/derpex/acme/*.ex`; tests with a fake ACME server ported from `../tailscale/cmd/derper/ipcert_test.go` `fakeIPACME`.
**Scope:** account creation with optional EAB (GCP), order, HTTP-01 challenge served on :80 via existing HTTP1, CSR (one DNS or one IP SAN), finalize, download; renew at 2/3 lifetime; cache to disk 0600. Spike first: evaluate any Hex ACME library against exact-parity requirements; expect to write it (JWS with ES256 via `:public_key`/`:jose` is the hard part). Flip F1's rejection and the pending rows to `ported` only when the fake-ACME tests pass.

---

## Cluster G — test honesty

### G1: Inventory generator emits all five dispositions
**Files:** `scripts/upstream_inventory.exs:217-228`, `interop/COVERAGE.md`.
**Behavior:** rows satisfied by an unchanged Go client → `black-box`; by the trace comparison → `differential`; every row must cite a DERPEX test file (generator fails otherwise). Add a CI step that regenerates and `git diff --exit-code`. Fix the two false implementation-specific rationales: `TestLookupDestHashTrieNoAlloc` → bench gains a `--fail-on` threshold and CI uses it; `TestDeps` → add `mix xref`/`deps.tree` allowlist check in `quality`.

### G2: Faithful TestSendFreeze
**Files:** `test/derpex/writer_test.exs:103` → move to `test/system/send_freeze_test.exs`.
**Behavior:** real listener, real sockets, `send_timeout: 100`, three clients; freeze bob's reads; alice → bob floods for 2 s; assert alice → cathy continues throughout (≥ 90 % delivered), bob is closed by write timeout, and `isEmpty(alice)` (alice receives nothing) — mirror `derp_test.go:464-540` assertion-for-assertion.

### G3: Property tests
**Files:** `mix.exs` (add `stream_data` test dep), new `test/property/frame_decoder_property_test.exs`, `http1_parser_property_test.exs`, `web_socket_frame_property_test.exs`, `client_info_property_test.exs`, `stun_protocol_property_test.exs`.
**Behavior:** arbitrary chunking of valid streams decodes identically; arbitrary bytes never raise and never allocate > declared caps (assert `:erlang.memory(:binary)` delta bounded). `mix test` runs them (100 runs each; `PROPERTY_RUNS=1000` for nightly).

### G4: Differential trace compares counters
**Files:** `interop/go/differential_trace.go`, `test/interop/differential_test.exs`, `lib/derpex/operations.ex`.
**Behavior:** after each scenario step snapshot `/debug/varz`-equivalent counters from both servers (Go via expvar; DERPEX via metrics endpoint) and compare the documented subset (`packets_sent`, `packets_dropped{reason}`, `peer_gone_*_frames`, `dup_client_*`, `unknown_frames`). Remove hardcoded constants from the trace; at least 3 scenarios (relay+drops, duplicates, watch/mesh).

### G5: server_info ordering and per-transport timeout tests
Covered by B5 and B10; ensure they are referenced from COVERAGE rows.

### G6: Real-signal system test and `mix test.system`
**Files:** new `test/system/signals_test.exs` (start the release in a port, send OS `SIGHUP` via `:os.cmd("kill -HUP pid")` — pid recorded from the port you spawned, never pattern-matched), `mix.exs` alias.

### G7: Remove dead code
`Derpex.Prober.Plan` → either wire into a `Derpex.Prober` runner started from config or delete with its test and update COVERAGE row for `TestDerpProber` to `pending`. `Contract.decode_lease/1`, `sign_lease/2`, `sign_revocation/2` → move signing into `test/support/gentility_signer.ex`; the release must not ship signing.

---

## Cluster H — pong semantics + remaining nits
- `handler.ex:450`: pong ring drops the **newer** ping when one is pending (Go). Test.
- `ring.ex:396-401`: feed head-dropped packets' residence time into the queue-duration EWMA.
- `router.ex:676-682`: `packets_forwarded_out` counts attempts.
- `bootstrap_dns.ex:158-163`: cap retained query strings at 256 bytes each.
- `lib.rs:73-78`: zeroize the stack key copy.
- `checksum-Elixir.Derpex.Crypto.Native.exs`: leave empty but add a `release.yml` step that fails if the manifest is empty on a non-prerelease tag.

---

## Final gate (Milestone 11 in PLAN.md)
1. `mix release.check` green locally and in CI.
2. `mix bench` with thresholds; record idle memory/connection, p99 relay latency in `docs/benchmarks/2026-MM-DD.md`.
3. Re-run the five-way review (data path, security, inventory, Gentility, Codex) against the branch; zero blockers.
4. Update PLAN.md status and COVERAGE.md; open PR `production-readiness` → `main`.
