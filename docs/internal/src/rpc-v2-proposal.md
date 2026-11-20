# RPC v2 proposal

The proposed [`miden.node.v2.NodeService`](../../../proto/proto/v2/rpc.proto) separates account headers, contents, code,
and witnesses. Small accounts can be loaded completely; large accounts can be executed by fetching entries lazily. This
proposal contains only a service definition for discussion.

## Account API

| Method                       | Returns                                                                                                           |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `GetAccountInfos`            | Account and storage headers for several public accounts at block N, optionally only if their commitments changed. |
| `GetAccountWitnesses`        | One partial SMT proving inclusion or absence at N for all requested public or private account IDs.                |
| `SyncAccount`                | Complete vault and map contents for a small public account, as a snapshot or delta to N.                          |
| `GetAccountVaultWitnesses`   | Inclusion/non-inclusion proofs for selected asset IDs at N.                                                       |
| `GetAccountStorageWitnesses` | Inclusion/non-inclusion proofs for selected keys across storage maps at N.                                        |

All state reads for an execution use the same explicit block N. Headers authenticate contents and entry proofs; account
witnesses authenticate headers against N's account root. An unchanged account can still need a fresh account witness
when the global account root changes.

`GetAccountInfos` returns one result per public account ID in request order: headers, `unchanged` if the supplied
commitment matches, or `not_found` if the account does not exist at N. A wallet can include accounts it has created
locally and still receive headers for its deployed accounts. Malformed requests and private IDs fail the batch with
`INVALID_ARGUMENT`.

`SyncAccount` accepts `(from, N]`; omitting `from` requests a snapshot. The server can return a snapshot even when a
delta was requested. It returns no headers, code, or witnesses. Its size limit, advertised by `GetLimits`, counts
storage slots, map entries, and vault assets at N. Accounts above it return `RESOURCE_EXHAUSTED`.

Deltas contain absolute values and explicit deletions, including keys lost when a map is removed and recreated under the
same name. The storage-map stream follows the same rule. The target storage header describes the slot layout. Clients
verify the resulting roots before using the state.

## Code registry

Clients keep the entire code-registry Merkle tree locally. `SyncCodeRegistry` streams procedures added during the
inclusive range `[N, M]`. Start at block 0 to bootstrap; after syncing through H, request `[H + 1, M]`. Each procedure
is sent once when registered, independently of how many accounts use it. An empty successful stream means no additions.

Apply additions and verify the resulting registry root against the authenticated commitment at M before accepting the
sync. Execution uses the local registry at its reference block, including any procedure witnesses needed; it does not
fetch code per account. Retain the registry version needed by running tasks. The procedure payload, leaf encoding, and
chain commitment will follow the protocol's code-registry design.

## Network transaction builder

### Migration

Synchronize the code registry through the reference block before spawning execution tasks. Tasks use that local
registry, request account information through `GetAccountInfos`, account witnesses through `GetAccountWitnesses`, and
vault/storage proofs lazily through the two entry-witness methods. All state reads use the task's reference block. This
is the migration baseline; account caches and a local account tree are optional.

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

1. Authenticate target N through `SyncChainMmr` and synchronize the code registry through N. Set `target_block_num`
   to execute at a historical block, or omit it to use the selected committed or proven tip. A target below the
   client's starting height returns `INVALID_ARGUMENT`. A target above the selected tip or outside retained history
   returns `OUT_OF_RANGE`.
2. To track account activity, consume `SyncTransactions` for the tracked IDs through N, including pass-through
   transactions whose account commitment stays the same. Each record supplies inclusion proofs for committed output
   notes. Outputs listed in the transaction header without a proof were erased. Use the final state commitment as a
   hint to refresh cached state. Clients interested only in public headers can call `GetAccountInfos` directly with
   their known commitments.
3. When a small public account needs refreshing, call `SyncAccount` from the last synchronized block to N and fetch
   its target headers. For large public accounts, fetch entry proofs lazily or download the contents through
   `SyncAccountVault` and `SyncAccountStorageMaps`. Owners retain private account state locally.
4. For execution, call `GetAccountWitnesses` for the required accounts at N. Verify the partial SMT against the
   authenticated account root at N, match each account header to its proven commitment, and verify the contents or
   entry proofs against that header. Execute using the code registry at N.

For example, a client preparing a foreign procedure invocation that already knows the foreign accounts, asset IDs,
and storage keys can request the public headers, batched account witnesses, and per-account vault and storage
witnesses concurrently at N. Once the responses arrive, the client can verify them together before execution.

Use `SyncNotes` and `SyncNullifiers` at the same target to discover notes and consumption. `GetTransactionsById`
reconciles known pending transactions. Accept stream results only after successful completion.

## Other methods

The service retains v1's status, limits, registration, allowlist, invitation, block/note retrieval, encryption key,
transaction submission, subscriptions, and network-note status methods.

This proposal adds the streaming APIs under discussion in [#2483](https://github.com/0xMiden/node/pull/2483). They
replace the paginated synchronization methods and use names without a `V2` suffix in the v2 service.
`GetTransactionsById` is also new. The account methods above replace `GetAccount`.

## Discussion points

- Should the other `SyncXxx` ranges also use a required, inclusive `from`, as `SyncCodeRegistry` does? Fresh loads would
  request `[0, N]`; clients holding state at C would request `[C + 1, N]`, skipping sync when already at N.
  If the lower bound becomes mandatory, how should `SyncAccount` distinguish a snapshot from a delta?
- Are the methods sufficient for execution, and are separate header, contents, and witness calls acceptable for clients
  tracking only a few accounts?
- Can the builder initialize its account tree through replay or a verified snapshot, or do we need an RPC bootstrap
  method?
