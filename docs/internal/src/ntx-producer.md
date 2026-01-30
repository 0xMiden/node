# Network Transaction Producer Component

The network transaction producer (NTP) is responsible for driving the state of network accounts.

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
that component. The NTP skirts around this by submitting its transactions directly to the
block-producer.

This limitation is there to prevent complicating the NTP's implementation while the protocol and
definitions of network accounts, notes and transactions mature.

## Implementation

On startup the mempool loads all unconsumed network notes from the store. From there it monitors
the mempool for events which would impact network account state. This communication takes the form
of an event stream via gRPC.

The NTP periodically selects an arbitrary network account with available network notes and creates
a network transaction for it.

The block-producer remains blissfully unaware of network transactions. From its perspective a
network transaction is simply the same as any other.
