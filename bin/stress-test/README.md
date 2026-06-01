# Miden node stress test

`stress-test` is a development binary for generating local store data and running stress tests against Miden node store
workflows. It is part of the Miden node repository but is not published as a crates.io package.

## Role

The binary can seed a local store with generated accounts and then run focused benchmarks against store operations such
as state loading, account lookup, note sync, nullifier sync, transaction sync, and chain MMR sync.

This tool is intended for development and performance investigation. Benchmark numbers are sensitive to hardware,
database contents, feature flags, and the exact commit under test, so the reference results below should be treated as a
point-in-time comparison rather than current guarantees.

## Operation

Use the binary help output for the current command and configuration surface. The help output is the source of truth for
flags and environment variables.

## Benchmark Results

The following reference results were obtained using a store with 100k accounts, half of which are public.

### Seed Metrics

```text
Total time: 235.452 seconds
Inserted 393 blocks with avg insertion time 212 ms
Initial DB size: 120.1 KB
Average DB growth rate: 325.3 KB per block
```

### Block Metrics

Each block contains 256 transactions (16 batches \* 16 transactions).

| Block | Insert Time (ms) | Get Block Inputs Time (ms) | Get Batch Inputs Time (ms) | Block Size (KB) | DB Size (MB) |
| ----- | ---------------- | -------------------------- | -------------------------- | --------------- | ------------ |
| 0     | 22               | 1                          | 0                          | 375.6           | 0.3          |
| 50    | 186              | 9                          | 1                          | 473.6           | 22.2         |
| 100   | 199              | 10                         | 1                          | 473.6           | 40.7         |
| 150   | 219              | 10                         | 1                          | 473.6           | 58.1         |
| 200   | 218              | 11                         | 1                          | 473.6           | 74.8         |
| 250   | 222              | 11                         | 1                          | 473.6           | 91.6         |
| 300   | 228              | 12                         | 1                          | 473.6           | 108.1        |
| 350   | 232              | 13                         | 1                          | 473.6           | 124.4        |

### Database Stats

The database contained 100215 accounts and 100215 notes across all blocks.

| Table                              | Size (MB) | KB/Entry |
| ---------------------------------- | --------- | -------- |
| accounts                           | 26.1      | 0.3      |
| account_deltas                     | 1.2       | 0.0      |
| account_fungible_asset_deltas      | 2.2       | 0.0      |
| account_non_fungible_asset_updates | 0.0       | -        |
| account_storage_map_updates        | 0.0       | -        |
| account_storage_slot_updates       | 3.1       | 0.1      |
| block_headers                      | 0.1       | 0.3      |
| notes                              | 49.1      | 0.5      |
| note_scripts                       | 0.0       | 8.0      |
| nullifiers                         | 4.6       | 0.0      |
| transactions                       | 6.0       | 0.1      |

### Index Stats

| Index                        | Size (MB) |
| ---------------------------- | --------- |
| idx_accounts_network_prefix  | 0.0       |
| idx_notes_note_id            | 4.4       |
| idx_notes_sender             | 2.9       |
| idx_notes_tag                | 1.6       |
| idx_notes_nullifier          | 4.4       |
| idx_unconsumed_network_notes | 1.1       |
| idx_nullifiers_prefix        | 4.3       |
| idx_nullifiers_block_num     | 4.2       |
| idx_transactions_account_id  | 5.6       |
| idx_transactions_block_num   | 4.2       |

### Store Stress Tests

Latency measurements represent pure store processing time without network overhead.

#### load-state

```text
State loaded in 42.959271667s
Database contains 99961 accounts and 99960 nullifiers
```

Account tree loading (~21.3s) and nullifier tree loading (~21.5s) were the primary bottlenecks; MMR loading and database
connection were negligible (<3ms each).

#### sync-notes

```text
Average request latency: 653.751us
P50 request latency: 606.417us
P95 request latency: 1.044666ms
P99 request latency: 1.528667ms
P99.9 request latency: 5.247875ms
```

#### sync-nullifiers

```text
Average request latency: 519.239us
P50 request latency: 503.708us
P95 request latency: 747.333us
P99 request latency: 873.083us
P99.9 request latency: 2.289709ms
Average nullifiers per response: 21.0348
```

#### sync-transactions

```text
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

#### sync-chain-mmr

```text
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

#### get-account

```text
Average request latency: 937.969us
P50 request latency: 688.332us
P95 request latency: 932.549us
P99 request latency: 1.119977ms
P99.9 request latency: 42.992839ms
GetAccount statistics:
  Total runs: 10000
  Storage map limit exceeded responses: 0
  Average returned storage map entries: 64.00
  Vault limit exceeded responses: 0
  Average returned vault assets: 2.00
```

## License

This project is [MIT licensed](../../LICENSE).
