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
- a held lock is retried a bounded number of times and then tail-dropped;
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

The retry budget is not an optimisation. Measured against the pinned Go DERP
prober (100 MB, thirty packets in flight, thirty-two ring slots, so the ring
always has room), a producer that made a single attempt lost roughly one packet
per fifteen hundred and failed the interop gate in a fifth of runs. Contended
acquisitions were rare — about seven in the whole transfer — but a few needed
hundreds of retries, because the holder can exhaust its reduction budget inside
the critical section and has to be rescheduled before it can release the lock.
Dropping a packet the ring has room for is a loss the Go relay does not take, so
producers yield the scheduler for a bounded number of attempts and then sleep
for a bounded number of further attempts before dropping.

What producers must not have is shared waiting state. An earlier revision
counted waiting producers and made the consumer defer to that count; a producer
killed while parked left the count non-zero forever, so every subsequent `take`
returned `:busy` and the connection's writer stalled permanently. Retrying
without a counter has no such window: the only shared state a dead producer can
leave is the lock itself, which the next caller reclaims from the recorded owner
pid.
