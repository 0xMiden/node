# RPC v2 proposal

The proposed [`miden.node.v2.NodeService`](../../../proto/proto/v2/rpc.proto) separates account headers, contents, code,
and witnesses. Small accounts can be loaded completely; large accounts can be executed by fetching entries lazily. This
proposal contains only a service definition for discussion.

## Account API

| Method                       | Returns                                                                                                           |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `GetAccountInfos`            | Account and storage headers for several public accounts at block N, optionally only if their commitments changed. |
| `GetAccountCode`             | Code by commitment, cached independently of account state.                                                        |
| `GetAccountWitness`          | An account inclusion or non-inclusion witness at N, for public or private accounts.                               |
| `SyncAccount`                | Complete vault and map contents for a small public account, as a snapshot or delta to N.                          |
| `GetAccountVaultWitnesses`   | Inclusion/non-inclusion proofs for selected asset IDs at N.                                                       |
| `GetAccountStorageWitnesses` | Inclusion/non-inclusion proofs for selected keys across storage maps at N.                                        |

All state reads for an execution use the same explicit block N. Headers authenticate contents and entry proofs; account
witnesses authenticate headers against N's account root. Code is verified against its commitment. An unchanged account
can still need a fresh account witness when the global account root changes.

`SyncAccount` accepts `(from, N]`; omitting `from` requests a snapshot. The server can return a snapshot even when a
delta was requested. It returns no headers, code, or witnesses. Its size limit, advertised by `GetLimits`, counts
storage slots, map entries, and vault assets at N. Accounts above it return `RESOURCE_EXHAUSTED`.

Deltas contain absolute values and explicit deletions, including keys lost when a map is removed and recreated under the
same name. The storage-map stream follows the same rule. The target storage header describes the slot layout. Clients
verify the resulting roots before using the state.

## Network transaction builder

### Migration

Execution tasks request account information and missing code through `GetAccountInfos` and `GetAccountCode`, account
witnesses through `GetAccountWitness`, and vault/storage proofs lazily through the two entry-witness methods. All state
reads use the task's reference block. This is the migration baseline; it requires no new account caches or local account
tree.

### Optimizations

1. **Small-account LRU.** Load complete accounts with `SyncAccount` and maintain them from the block stream. Pass a task
   the cached account and chain MMR at its reference block. Cache misses fetch asynchronously. Before returning a
   committed account copy to the LRU, catch it up with `SyncAccount`; speculative transaction output stays separate.
2. **Local account tree.** Maintain an `AccountTree` from the block stream to generate account witnesses locally.
   Initialization, persistence across restarts, and access to older tree versions for running tasks need a design.
3. **Large-account LRU.** Caching frequently accessed accounts, such as the USDCx faucet and AggLayer account, could
   reduce lazy RPC reads. This needs more thought, particularly how tasks retain a consistent view without cloning large
   accounts on every block.

## Clients and monitors

Clients tracking a few accounts do not need a local account tree:

1. Authenticate target N through `SyncChainMmr`.
2. Call `GetAccountInfos` with known commitments, or use `SyncAccountCommitments` to discover changed accounts before
   fetching their headers.
3. For small accounts, call `SyncAccount` from the last synchronized block to N. For large accounts, either fetch
   witnesses lazily or download complete contents through `SyncAccountVault` and `SyncAccountStorageMaps`.
4. Fetch missing code by commitment. Obtain `GetAccountWitness` at N when needed for execution, unless the commitment
   stream already supplied it. Owners retain private account state locally.

At the same target, use `SyncNotes`, `SyncNullifiers`, and `SyncTransactions` to discover notes, consumption, and
account activity. `GetTransactionsById` reconciles known pending transactions. Accept stream results only after
successful completion and verify proofs and final account roots against authenticated chain state.

## Other methods

The service retains v1's status, limits, registration, allowlist, invitation, block/note retrieval, encryption key,
transaction submission, chain-MMR, subscriptions, and network-note status methods.

This proposal adds the streaming APIs under discussion in [#2483](https://github.com/0xMiden/node/pull/2483). They
replace the paginated synchronization methods and use names without a `V2` suffix in the v2 service.
`SyncAccountCommitments` and `GetTransactionsById` are also new. The account methods above replace `GetAccount`.

## Discussion points

- Should `from` be required and inclusive across `SyncXxx`? Fresh loads would request `[0, N]`; clients holding state at
  C would request `[C + 1, N]`, skipping content synchronization when already at N.
- Are the methods sufficient for execution, and are separate header, contents, and witness calls acceptable for clients
  tracking only a few accounts?
- Should `GetAccountInfos` fail the whole batch for a missing/private account, as currently proposed, or return a result
  per account?
- Should account witnesses and code fetching also support batches?
- Can the builder initialize its account tree through replay or a verified snapshot, or do we need an RPC bootstrap
  method?
