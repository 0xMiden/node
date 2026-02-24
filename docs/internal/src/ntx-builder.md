# Network Transaction Builder Component

The network transaction builder (NTB) is responsible for driving the state of network accounts.

## What is a network account

Network accounts are a special type of fully public account which contains no authentication and
whose state can therefore be updated by anyone (in theory). Such accounts are required when publicly
mutable state is needed.

The issue with publicly mutable state is that transactions against an account must be sequential
and require the previous account commitment in order to create the transaction proof. This conflicts
with Miden's client side proving and concurrency model since users would race each other to submit
transactions against such an account.

Instead the solution is to have the network be responsible for driving the account state forward,
and users can interact with the account using notes. Notes don't require a specific ordering and
can be created concurrently without worrying about conflicts. We call these network notes and they
always target a specific network account.

A network transaction is a transaction which consumes and applies a set of network notes to a
network account. There is nothing special about the transaction itself - it can only be identified
by the fact that it updates the state of a network account.

## Limitations

At present, we artificially limit this such that only this component may create transactions against
network accounts. This is enforced at the RPC layer by disallowing network transactions entirely in
that component. The NTB skirts around this by submitting its transactions directly to the
block-producer.

This limitation is there to prevent complicating the NTBs implementation while the protocol and
definitions of network accounts, notes and transactions mature.

## Implementation

The NTB uses an actor-per-account model managed by a central `Coordinator`. On startup the
coordinator syncs all known network accounts and their unconsumed notes from the store. It then
monitors the mempool for events (via a gRPC event stream from the block-producer) which would
impact network account state.

For each network account that has available notes, the coordinator spawns a dedicated
`AccountActor`. Each actor runs in its own async task and is responsible for creating transactions
that consume network notes targeting its account. Actors read their state from the database and
re-evaluate whenever notified by the coordinator.

Actors that have been idle (no available notes to consume) for longer than the **sterility
timeout** will request shutdown from the coordinator. The coordinator validates the request against
the database before approving: if notes are still available, the request is rejected and the actor
resumes. The sterility timeout is configurable via the `--ntx-builder.sterility-timeout` CLI
argument (default: 5 minutes).

Deactivated actors are re-spawned when new notes targeting their account are detected by the
coordinator (via the `send_targeted` path).

The block-producer remains blissfully unaware of network transactions. From its perspective a
network transaction is simply the same as any other.
