# ADR 0001: fixed ETS outbox rings

Status: accepted for the Milestone 1 implementation.

## Context

A slow DERP recipient must not grow another BEAM process's mailbox or block a
sender. Go uses bounded, non-blocking channels with drop-head replacement. A
plain GenServer queue would make mailbox size the real, unbounded capacity.

## Decision

Each packet class uses a `Derpex.Outbox.Ring` with exactly the configured number
of ETS packet slots. Head, size, wake state, closure, and counters live in
`:atomics`. Producers make a single lock attempt:

- an uncontended enqueue publishes directly into a fixed slot;
- a full ring overwrites the oldest slot and advances the head;
- lock contention is an immediate tail drop;
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
committed or recovered.

## Consequences

The structure has an auditable memory ceiling and stalled writers receive no
repeated wakeups. The ring is ETS-owner lifetime-bound and is intentionally
single-consumer. Ordinary, disco, and control traffic receive separate rings or
bounded single-slot structures at the Outbox layer.

Tail drops are an expected outcome, not an error path. A producer that finds the
lock held drops the packet immediately and increments `tail_drops` plus the
`queue_tail` drop metric for the ring's packet class, so contention is always
visible in the counters rather than paid for in sender latency. The drop rate
rises with the number of senders that fan into one destination at once: eight
producers enqueuing in a tight loop (no work between packets) turn most attempts
into counted tail drops, while producers that spend a few hundred microseconds
per packet — the realistic relay case — see a small percentage. This is the
deliberate trade for the invariant that a sender's reader is never suspended by
a destination's queue.

Producers make exactly one lock attempt because any waiting scheme requires
shared "someone is waiting" state, and a producer killed inside that window
leaves the state behind. An earlier revision let producers retry for a few
milliseconds and made the consumer defer to waiting producers; a producer killed
while parked left the waiter count non-zero forever, so every subsequent `take`
returned `:busy` and the connection's writer stalled permanently. A single
attempt has no such window: the only shared state a dead producer can leave is
the lock itself, which the next caller reclaims from the recorded owner pid.
