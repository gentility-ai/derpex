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
repeated wakeups. A producer can tail-drop during a very short critical section;
this matches the allowed concurrent-admission fallback. The ring is ETS-owner
lifetime-bound and is intentionally single-consumer. Ordinary, disco, and
control traffic receive separate rings or bounded single-slot structures at
the Outbox layer.
