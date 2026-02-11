# Miden stress test

This crate contains a binary for running Miden node stress tests.

## Seed Store

This command seeds a store with newly generated accounts. For each block, it first creates a faucet transaction that sends assets to multiple accounts by emitting notes, then adds transactions that consume these notes for each new account. As a result, the seeded store files are placed in the given data directory, including a dump file with all the newly created accounts ids.

Once it's finished, it prints out several metrics.

After building the binary, you can run the following command to generate one million accounts:

`miden-node-stress-test seed-store --data-directory ./data --num-accounts 1000000`

The store file will then be located at `./data/miden-store.sqlite3`.

## Benchmark Store

This command allows to run stress tests against the Store component. These tests use the dump file with accounts ids created when seeding the store, so be sure to run the `seed-store` command beforehand.

The endpoints that you can test are:
- `load_state`
- `sync_notes`
- `sync_nullifiers`
- `sync_transactions`
- `sync-chain-mmr`

Most benchmarks accept options to control the number of iterations and concurrency level. The `load_state` endpoint is different - it simply measures the one-time startup cost of loading the state from disk.

**Note on Concurrency**: For the endpoints that support it (`sync_notes`, `sync_nullifiers`), the concurrency parameter controls how many requests are sent in parallel to the store. Since these benchmarks run against a local store (no network overhead), higher concurrency values can help identify bottlenecks in the store's internal processing. The latency measurements exclude network time and represent pure store processing time.

Example usage:

```bash
miden-node-stress-test benchmark-store \
  --data-directory ./data \
  --iterations 10000 \
  --concurrency 16 \
  sync-notes
```

### Results

The following results were obtained using a store with 100k accounts, half of which are public.

Using the store seed command:
```bash
# Using 100k accounts, half are public
$ miden-node-stress-test seed-store --data-directory data --num-accounts 100000 --public-accounts-percentage 50

Total time: 235.452 seconds
Inserted 393 blocks with avg insertion time 212 ms
Initial DB size: 120.1 KB
Average DB growth rate: 325.3 KB per block
```

#### Block metrics

> Note: Each block contains 256 transactions (16 batches * 16 transactions).

| Block  | Insert Time (ms)   |  Get Block Inputs Time (ms)   |  Get Batch Inputs Time (ms)    | Block Size (KB)    |  DB Size (MB) |
| ------ | ------------------ | ----------------------------- | ------------------------------ | ------------------ | ------------- |
| 0      | 22                 | 1                             | 0                              | 375.6              | 0.3           |
| 50     | 186                | 9                             | 1                              | 473.6              | 22.2          |
| 100    | 199                | 10                            | 1                              | 473.6              | 40.7          |
| 150    | 219                | 10                            | 1                              | 473.6              | 58.1          |
| 200    | 218                | 11                            | 1                              | 473.6              | 74.8          |
| 250    | 222                | 11                            | 1                              | 473.6              | 91.6          |
| 300    | 228                | 12                            | 1                              | 473.6              | 108.1         |
| 350    | 232                | 13                            | 1                              | 473.6              | 124.4         |

#### Database stats

> Note: Database contains 100215 accounts and 100215 notes across all blocks.

| Table                              | Size (MB)       | KB/Entry   |
| ---------------------------------- | --------------- | ---------- |
| accounts                           | 26.1            | 0.3        |
| account_deltas                     | 1.2             | 0.0        |
| account_fungible_asset_deltas      | 2.2             | 0.0        |
| account_non_fungible_asset_updates | 0.0             | -          |
| account_storage_map_updates        | 0.0             | -          |
| account_storage_slot_updates       | 3.1             | 0.1        |
| block_headers                      | 0.1             | 0.3        |
| notes                              | 49.1            | 0.5        |
| note_scripts                       | 0.0             | 8.0        |
| nullifiers                         | 4.6             | 0.0        |
| transactions                       | 6.0             | 0.1        |

#### Index stats

| Index                              | Size (MB)       |
| ---------------------------------- | --------------- |
| idx_accounts_network_prefix        | 0.0             |
| idx_notes_note_id                  | 4.4             |
| idx_notes_sender                   | 2.9             |
| idx_notes_tag                      | 1.6             |
| idx_notes_nullifier                | 4.4             |
| idx_unconsumed_network_notes       | 1.1             |
| idx_nullifiers_prefix              | 4.3             |
| idx_nullifiers_block_num           | 4.2             |
| idx_transactions_account_id        | 5.6             |
| idx_transactions_block_num         | 4.2             |


Current results of the store stress-tests:

**Performance Note**: The latency measurements below represent pure store processing time (no network overhead).

*The following results were obtained after seeding the store with the command used previously.*

- load-state
``` bash
$ miden-node-stress-test benchmark-store --data-directory ./data load-state

State loaded in 42.959271667s
Database contains 99961 accounts and 99960 nullifiers
```

**Performance Note**: The load-state benchmark shows that account tree loading (~21.3s) and nullifier tree loading (~21.5s) are the primary bottlenecks, while MMR loading and database connection are negligible (<3ms each).

- sync-notes
``` bash
$ miden-node-stress-test benchmark-store --data-directory ./data --iterations 10000 --concurrency 16 sync-notes

Average request latency: 653.751µs
P50 request latency: 606.417µs
P95 request latency: 1.044666ms
P99 request latency: 1.528667ms
P99.9 request latency: 5.247875ms
```

- sync-nullifiers
``` bash
$ miden-node-stress-test benchmark-store --data-directory ./data --iterations 10000 --concurrency 16 sync-nullifiers --prefixes 10

Average request latency: 519.239µs
P50 request latency: 503.708µs
P95 request latency: 747.333µs
P99 request latency: 873.083µs
P99.9 request latency: 2.289709ms
Average nullifiers per response: 21.0348
```

- sync-transactions
``` bash
$ miden-node-stress-test benchmark-store --data-directory ./data --iterations 10000 --concurrency 16 sync-transactions --accounts 5 --block-range 100

Average request latency: 1.61454ms
P50 request latency: 1.439584ms
P95 request latency: 3.195001ms
P99 request latency: 4.068709ms
P99.9 request latency: 6.888542ms
Average transactions per response: 1.547
Pagination statistics:
  Total runs: 10000
  Runs triggering pagination: 9971
  Pagination rate: 99.71%
  Average pages per run: 2.00
```

- sync-chain-mmr
``` bash
$ miden-node-stress-test benchmark-store --data-directory ./data --iterations 10000 --concurrency 16 sync-chain-mmr --block-range 1000

Average request latency: 1.021ms
P50 request latency: 0.981ms
P95 request latency: 1.412ms
P99 request latency: 1.822ms
P99.9 request latency: 3.174ms
Pagination statistics:
  Total runs: 10000
  Runs triggering pagination: 1
  Pagination rate: 0.01%
  Average pages per run: 1.00
```

## License
This project is [MIT licensed](../../LICENSE).
