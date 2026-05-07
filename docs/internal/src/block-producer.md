# Block Producer Component

The block-producer is responsible for ordering transactions into batches, and batches into blocks, and creating the
proofs for batches. Proving is usually outsourced to a remote prover but can be done locally if throughput isn't
essential, e.g. for test purposes on a local node.

The core of the block-producer revolves around the mempool which forms a DAG of all in-flight transactions and batches.
It also ensures all invariants of the transactions are upheld e.g. account's current state matches the transaction's
initial state, that all input notes are valid and unconsumed and that the transaction hasn't expired.

## Batch production

Transactions are selected from the mempool periodically to form batches. This batch is then proven and submitted back to
the mempool where it can be included in a block.

## Block production

Proven batches are selected from the mempool periodically to form the next block. The block is then built and sent to the
validator for verification and signing.
This signed block is then submitted to the store where it gets proven and committed. Proof
generation in production is typically 
outsourced to a remote machine with appropriate resources. For convenience,
it is also possible to perform proving in-process. This is useful when running a local node for test purposes.

Once the block is committed,  all transactions and batches in the block are marked in the mempool as committed.

## Mempool data pruning

The mempool keeps the `N` most recent blocks locally, to allow incoming transactions a grace period so we can verify their
state against the store, and the local state deltas in the mempool. Without this overlap, we would constantly be racing
transaction check against the store with newly committed blocks.

After each now block, the `N+1`th oldest block and its batches and transactionsa are pruned from the mempool state.

## Transaction lifecycle

1. Transaction arrives at RPC component
2. Transaction proof is verified
3. Transaction arrives at block-producer
4. Transaction delta is verified
   - Does the account state match
   - Do all input notes exist and are unconsumed
   - Output notes are unique
   - Transaction is not expired
5. Wait until all parent transactions are in a batch
6. Be selected as part of a batch
7. Proven as part of a batch
8. Wait until all parent batches are in a block
9. Be selected as part of a block
10. Committed

Note that its possible for transactions to be rejected/dropped even after they've been accepted, at any point in the
above lifecycle (which effectively shows the happy path). This can occur if:

- The transaction expires before being included in a block.
- Any parent transaction is dropped (which will revert the state, invalidating child transactions).
- It causes proving or any part of block/batch creation to fail repeatedly. This is a fail-safe against unforeseen bugs, removing
  problematic (but potentially valid) transactions from the mempool to prevent outages.
