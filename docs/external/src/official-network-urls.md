---
title: "Official Network URLs"
sidebar_position: 3
---

# Official Network URLs

Official network URLs are the public entry points for Miden networks. Use the URL that matches the network you are
targeting.

Official services generally use the following URL format:

```text
https://<service>.<network>.miden.io
```

| Service     | Testnet                                                                  | Devnet                                                                 | Notes                                                      |
| ----------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ---------------------------------------------------------- |
| `rpc`       | [https://rpc.testnet.miden.io](https://rpc.testnet.miden.io)             | [https://rpc.devnet.miden.io](https://rpc.devnet.miden.io)             | Public gRPC and gRPC-Web API endpoint.                     |
| `genesis`   | [https://genesis.testnet.miden.io](https://genesis.testnet.miden.io)     | [https://genesis.devnet.miden.io](https://genesis.devnet.miden.io)     | Hosted signed genesis block for bootstrapping.             |
| `tx-prover` | [https://tx-prover.testnet.miden.io](https://tx-prover.testnet.miden.io) | [https://tx-prover.devnet.miden.io](https://tx-prover.devnet.miden.io) | Transaction proving service.                               |
| `explorer`  | [https://explorer.testnet.miden.io](https://explorer.testnet.miden.io)   | [https://explorer.devnet.miden.io](https://explorer.devnet.miden.io)   | Midenscan block explorer.                                  |
| `status`    | [https://status.testnet.miden.io](https://status.testnet.miden.io)       | [https://status.devnet.miden.io](https://status.devnet.miden.io)       | Network monitor webpage.                                   |
| `transport` | [https://transport.testnet.miden.io](https://transport.testnet.miden.io) | [https://transport.devnet.miden.io](https://transport.devnet.miden.io) | Note transport layer.                                      |
| `faucet`    | [https://faucet.testnet.miden.io](https://faucet.testnet.miden.io)       | [https://faucet.devnet.miden.io](https://faucet.devnet.miden.io)       | Public faucet for obtaining funds on the selected network. |

## RPC API

The public RPC endpoints use TLS. Tools such as `grpcurl` use the host name and port `443`:

```bash
grpcurl rpc.testnet.miden.io:443 rpc.Api/Status
```

See [gRPC API](/rpc) for schema discovery, endpoint groups, subscriptions, limits, and method-specific errors.

## Genesis Block

Bootstrap commands can use the network name instead of downloading the genesis block URL directly:

```bash
miden-node bootstrap \
  --data-directory full-node-data \
  --network testnet
```

Use `--network devnet` for devnet.
