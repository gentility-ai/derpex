# ADR 0003: unbounded lifecycle queue with a soft cap

Status: accepted.

## Context

Presence frames are not traffic. A `peer_present` or `peer_gone` frame records
that the region changed, and nothing later in the stream corrects a dropped
one: a watcher that misses a `peer_present` believes a peer is absent until that
peer leaves and rejoins, and a watcher that misses a `peer_gone` believes a peer
is present until it comes back. Go stores these in `sclient.peerStateChange`, a
slice that grows with no cap.

ADR 0001 gives every packet class a fixed ring that replaces its oldest entry
when full. Applying that to lifecycle frames made a watcher's view of the region
silently wrong the moment more than thirty-two peers arrived while its writer
was busy — which is exactly what happens when a mesh peer connects to a region
that is already full of clients.

## Decision

Lifecycle frames get `Derpex.Outbox.LifecycleQueue`: an ETS `ordered_set` keyed
by `{:item, sequence}`, using the same lock, wake flag and drain protocol as
`Derpex.Outbox.Ring` (both share `Derpex.Outbox.Lock`, and `Derpex.Outbox`
dispatches between them, so the writer, the router and the drain coordinator do
not care which one they hold).

- The queue has no capacity. Every state change is retained in arrival order.
- Item keys are tuples and the lock key is an atom, which sorts before every
  tuple, so the oldest item is `:ets.next(table, :lock)`.
- A mutation is a single insert or delete, so there is no journal: a producer
  killed mid-enqueue either inserted its frame or did not, and the consumer
  reads the table rather than a separate counter, so neither outcome can strand
  a frame.
- Packets keep their fixed rings. Only lifecycle frames live here.

There is a **soft cap** of 65,536 frames. Beyond it the queue refuses the frame,
counts `derp_lifecycle_queue_overflows`, and tells its owner — the connection —
to close, which the handler does with a logged reason.

## Consequences

A watcher's view of the region is now either complete or absent. It cannot be
partially wrong, which was the failure mode a fixed ring produced and no
observer could detect.

The soft cap is a documented deviation from Go, recorded in PLAN section 2.3.
Go's slice grows without limit, so a watcher that stops reading in a large
region can grow a Go relay's memory without bound; DERPEX closes that watcher
instead. The threshold is deliberately far above any legitimate backlog: at
65,536 frames a watcher is more than a full region behind and has not read for
long enough that catching up would deliver a view of the past. Closing it is
the only action that both bounds memory and avoids handing out a wrong view,
and a mesh watcher reconnects and takes a fresh snapshot.

Memory is bounded by the soft cap rather than by a constant: 65,536 retained
frames is the worst case per watcher, against 32 for a ring. The ordinary case
is a queue that is empty except while the writer is mid-drain, because a
lifecycle frame is drained before any packet.
