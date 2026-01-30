# Navigating the codebase

The code is organised using a Rust workspace with separate crates for the node and remote prover binaries, a crate for each node
component, a couple of gRPC-related codegen crates, and a catch-all utilities crate.

The primary artifacts are the node and remote prover binaries. The library crates are not intended for external usage, but
instead simply serve to enforce code organisation and decoupling.

| Crate                  | Description                                                                                                                                              |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `node`                 | The node executable. Configure and run the node and its components.                                                                                      |
| `remote-prover`        | Remote prover executables. Includes workers and proxies.                                                                                                 |
| `remote-prover-client` | Remote prover client implementation.                                                                                                                     |
| `block-producer`       | Block-producer component implementation.                                                                                                                 |
| `store`                | Store component implementation.                                                                                                                          |
| `ntx-producer`         | Network transaction producer component implementation.                                                                                                   |
| `rpc`                  | RPC component implementation.                                                                                                                            |
| `proto`                | Contains and exports all protobuf definitions.                                                                                                           |
| `rpc-proto`            | Contains the RPC protobuf definitions. Currently this is an awkward clone of `proto` because we re-use the definitions from the internal protobuf types. |
| `utils`                | Variety of utility functionality.                                                                                                                        |
| `test-macro`           | Provides a procedural macro to enable tracing in tests.                                                                                                  |

---

> [!NOTE] > [`miden-base`](https://github.com/0xMiden/miden-base) is an important dependency which
> contains the core Miden protocol definitions e.g. accounts, notes, transactions etc.

[![workspace dependency tree](assets/workspace_tree.svg)](assets/workspace_tree.svg)
