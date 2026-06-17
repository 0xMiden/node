# Network Transaction Builder Component

The network transaction builder (NTB) is responsible for driving the state of network accounts.

## What is a network account

Network accounts are a special type of fully public account which contains no authentication and
whose state can therefore be updated by anyone (in theory). Such accounts are required when publicly
mutable state is needed.

An issue with publicly mutable state is that transactions against an account must be sequential
and require the previous account commitment in order to create the transaction proof. This conflicts
with Miden's client side proving and concurrency model since users would race each other to submit
transactions against such an account.

Instead our solution is to have the network be responsible for driving the account state forward,
and users can interact with the account only indirectly using notes. Notes don't require a specific ordering and
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
follows the committed block stream from the RPC service for updates which would impact network
account state.

For each network account, the coordinator spawns a dedicated `AccountActor`. Each actor runs in
its own async task and is responsible for creating transactions that consume network notes targeting
its account. On startup, each actor waits until its account has been committed to the chain before
producing any transactions. This means newly created network accounts will idle until their creation
transaction is included in a block. Once the committed state is available, the actor reads its state
from the database and re-evaluates whenever notified by the coordinator.

Actors that have been idle (no available notes to consume) for longer than the **idle timeout**
will be deactivated. The idle timeout is configurable via the `--ntx-builder.idle-timeout` CLI
argument (default: 5 minutes).

Deactivated actors are re-spawned when committed-chain processing detects new notes targeting their
account.

Each actors crash count is tracked, and once the count reaches a configurable threshold, the account is 
**deactivated** and no new actor will be spawned for it. This prevents resource exhaustion from a persistently
failing account. The threshold is configurable via the `--ntx-builder.max-account-crashes` CLI
argument (default: 10).

The block-producer remains blissfully unaware of network transactions. From its perspective a
network transaction is simply the same as any other.

## gRPC Server

The NTX exposes an internal gRPC server for querying its state. The RPC component proxies public
requests to this server. In bundled mode the server is started automatically on a random port and
wired to the RPC; in distributed mode operators must pass the NTB's address to the RPC via
`--ntx-builder.url` (or `MIDEN_NODE_NTX_BUILDER_URL`).

Currently the only endpoint is `GetNetworkNoteStatus(note_id)` which returns the lifecycle status
of a network note (pending, processed, or discarded), along with the latest execution error,
attempt count, and block number of the last attempt. This is useful for debugging notes that fail
to be consumed.
