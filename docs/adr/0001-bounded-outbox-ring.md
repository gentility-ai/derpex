# ADR 0001: fixed ETS outbox rings

Status: accepted for the Milestone 1 implementation.

## Context

A slow DERP recipient must not grow another BEAM process's mailbox or block a
sender. Go uses bounded, non-blocking channels with drop-head replacement. A
plain GenServer queue would make mailbox size the real, unbounded capacity.

## Decision

Each packet class uses a `Derpex.Outbox.Ring` with exactly the configured number
of ETS packet slots. Head, size, wake state, closure, and counters live in
`:atomics`. Producers keep no shared waiting state:

- an uncontended enqueue publishes directly into a fixed slot;
- a full ring overwrites the oldest slot and advances the head;
- a held lock is retried inside a wall-clock budget and then tail-dropped;
- the writer receives one coalesced atom and pulls packets from ETS;
- no packet or packet reference is sent to a process mailbox.

The ETS lock records its owning PID. A mutation journal records only the slot
index, unique operation token, and target counters. If a process dies during a
mutation, the next caller reclaims the dead owner's lock and either commits a
published slot or discards an unpublished reservation. Closing clears all
slots and prevents further publication.

The single writer drains until `:empty`; observing empty clears the wake flag
while holding the lock. Enqueue signals before publication while holding that
same lock, so the consumer cannot observe the wake before the operation is
committed or recovered. A writer that finds a ring locked ends the drain and
schedules one short retry: it never re-sends itself a wakeup, because the
producer holding the lock may have coalesced its signal into the wakeup being
handled, and a self-wakeup would then spin until that producer commits. The
writer also drains once when its rings are attached, since a wakeup raised
before attachment has no rings to drain and is not repeated.

## Consequences

The structure has an auditable memory ceiling and stalled writers receive no
repeated wakeups. The ring is ETS-owner lifetime-bound and is intentionally
single-consumer. Ordinary, disco, and control traffic receive separate rings or
bounded single-slot structures at the Outbox layer.

Tail drops are an expected outcome, not an error path. A producer that cannot
take the lock within its retry budget drops the packet and increments
`tail_drops` plus the `queue_tail` drop metric for the ring's packet class, so
contention is always visible in the counters. The drop rate rises with the
number of senders that fan into one destination at once: eight producers
enqueuing in a tight loop (no work between packets) turn most attempts into
counted tail drops, while a realistic relay flow drops none.

The retry budget is a deliberate, documented deviation from PLAN §3.3 and §3.5,
which say a sender enqueues without ever being suspended. A sender can be
suspended here, by up to the acquisition budget of about four milliseconds, and
only when the destination ring's lock is held that long.

The deviation is not an optimisation. Measured against the pinned Go DERP prober
(100 MB in 1526 packets, thirty in flight, thirty-two ring slots, so the ring
always has room), producers that made a single lock attempt failed the interop
gate in four runs out of ten; each failing run showed exactly one counted tail
drop, and one lost packet is enough, because the prober compares payloads in
order. Contention itself is rare: with the current budget, instrumented runs of
the same transfer showed between zero and twelve retried attempts each, and the
nap tier fired once across eight transfers. What makes the rare case expensive is
that the lock holder can exhaust its reduction budget inside the critical section
and has to be rescheduled before it can release. Dropping a packet the ring has
room for is a loss the Go relay does not take.

The budget is bounded by the wall clock rather than by an attempt count, because
`:erlang.yield/0` returns in microseconds on an idle node and in tens of
milliseconds behind a long run queue, so a fixed number of yields is not a bound
on anything. Producers yield a few times, then nap in one-millisecond steps, and
every tier re-checks the same deadline. Each nap increments
`derp_ring_producer_naps`, so a relay that starts paying the budget says so.

Callers that must never sleep on behalf of one destination pass `wait: false`,
which keeps the yield tier and drops the naps. The router and the drain
coordinator use it: they are singletons, and a millisecond spent waiting for one
connection's writer is a millisecond every other connection waits too.

What producers must not have is shared waiting state. An earlier revision
counted waiting producers and made the consumer defer to that count; a producer
killed while parked left the count non-zero forever, so every subsequent `take`
returned `:busy` and the connection's writer stalled permanently. Retrying
without a counter has no such window: the only shared state a dead producer can
leave is the lock itself, which the next caller reclaims from the recorded owner
pid.
