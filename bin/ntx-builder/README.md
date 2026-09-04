# Miden network transaction builder

`miden-ntx-builder` is a Miden node binary that creates network transactions for network accounts. It is part of the
Miden node repository; see the [repository README](https://github.com/0xMiden/node#readme) for the overall project
layout.

## Role

The network transaction builder syncs blocks from an upstream node, tracking network notes and accounts. On every
committed block it picks the network accounts that have pending notes and spawns one short-lived transaction attempt per
account, up to a configured concurrency limit. Each attempt selects viable notes, constructs a transaction, proves it,
and submits the proven transaction back through the upstream node's RPC API.

The builder can use a remote transaction prover through `miden-remote-prover`, or fall back to in-process proving where
appropriate for local development. It also exposes an internal gRPC API that the node RPC component can use for
network-note status queries.

## Operation

The builder has its own persistent database and must be initialized from the same trusted genesis block as the rest of
the network before it starts. In a complete node deployment, `node` connects to this service so network-note status can
be exposed through the public RPC API.

## Benchmarks

`benches/large_account.rs` measures the cost of a large network account, which every transaction attempt loads from the
database. It synthesizes a network account with a populated storage map and reports resident/peak heap, serialized size,
and per-operation timings. Per-candidate cost is not a factor: the account is shared via `Arc`, and
`PartialAccount::from` is constant-time in the map size for existing accounts.

```bash
# Default sizes (1k, 10k, 100k entries).
cargo bench -p miden-ntx-builder --bench large_account

# Custom sizes (entries per storage map). 1M needs several GiB of RAM, so it is opt-in:
cargo bench -p miden-ntx-builder --bench large_account -- 1000 100000 1000000
```

## License

This project is [MIT licensed](../../LICENSE).
