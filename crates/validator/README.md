# Miden Validator

The Miden Validator is a temporary component of the Miden node that provides transaction validation and block signing services for the Miden network. It is a core component of the network's "guardrails" that provide additional validation and assurances while the protocol is in active development.

## Overview

The validator component is responsible for:

- **Transaction Validation**: Receiving and re-executing proven transactions from the RPC layer.
- **Transaction Storage**: Persisting re-executed transaction data for block verification and signing.
- **Block Validation**: Verifying blocks produced by the block producer using stored transaction information.
- **Block Signing**: Cryptographically signing valid blocks as part of the consensus process.

## Architecture

The validator operates as a gRPC server and integrates with other Miden node components according to the following flow:

```mermaid
sequenceDiagram
    participant Client
    participant RPC
    participant Validator
    participant BlockProducer as Block Producer
    participant Store
    participant RemoteProver as Remote Prover

    Note over Client, Validator: Transaction Submission
    Client->>RPC: SubmitProvenTransaction()

    Note over RPC, Validator: Transaction Validation

    RPC->>RPC: Validate transaction
    RPC->>Validator: Submit transaction
    Validator->>Validator: Validate transaction
    Validator->>Validator: Store transaction
    Validator->>RPC: Accepted
    RPC->>Client: OK


    Note over BlockProducer, RPC: Block Building
    RPC->>BlockProducer: Forward valid transaction
    BlockProducer->>BlockProducer: Build proposed block

    Note over BlockProducer, Validator: Block Validation
    BlockProducer->>Validator: Proposed block
    Validator->>Validator: Check block validity using stored tx info
    Validator->>BlockProducer: Signed block header
    BlockProducer->>BlockProducer: Signed Block
    BlockProducer->>Store: Signed block

    Note over Store, RemoteProver: Block Proving
    Store->>RemoteProver: Signed block
    RemoteProver->>Store: Block proof
    Store->>Store: Proven block
```

## Current Status

> [!WARNING]
> The validator is currently a **work in progress** and under active development. Many features described above are not yet fully implemented.

### Implemented Features

- ✅ Protobuf schema and gRPC server scaffolding.
- ✅ Transaction submission handler.
- ✅ Transaction re-execution logic.
- ✅ Database schema and impl.
- ✅ Block validation logic.
- ✅ Block signing logic (AWS KMS and local).
- ✅ Integration with RPC.
- ✅ Integration with block producer consensus.

## API

The validator exposes a gRPC API with the following endpoints:

- `Status()` - Returns validator health and version information.
- `SubmitProvenTransaction()` - Validates and stores a proven transaction.
- `ValidateBlock()` - Validates a block and returns a signature (TODO).

## Configuration

The validator requires:

- **Address**: Network address for the gRPC server.
- **gRPC Timeout**: Request timeout duration.
- **Data Directory**: Path for SQLite database files.

## License

This project is [MIT licensed](../../LICENSE).
