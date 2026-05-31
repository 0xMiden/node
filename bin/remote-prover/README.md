# Miden remote prover

`miden-remote-prover` is a gRPC server for generating Miden transaction, batch, or block proofs on a
machine separate from the caller. It is part of the Miden node repository; see the
[repository README](https://github.com/0xMiden/node#readme) for the overall project layout.

## Role

Remote proving lets weaker clients or node components offload expensive proof generation to a machine
with more suitable resources. Each server instance is configured for one proof type. Requests are
accepted up to a configured capacity and processed by the prover service.

The service is intentionally small: it provides the proving API, worker status API, gRPC health
checking, gRPC reflection, gRPC-Web support, and OpenTelemetry tracing. More complex proxying or
load-balancing should be handled outside this binary.

The protobuf service definition is versioned with the Miden node repository. When integrating
directly with the protocol, use definitions matching the deployed binary. For project navigation and
documentation links, see the [primary README](https://github.com/0xMiden/node#readme).

## License

This project is [MIT licensed](../../LICENSE).
