# Miden block producer

Contains code defining the [Miden node's block-producer](/README.md#architecture) component. It is responsible for
ordering transactions into blocks and submitting these for inclusion in the blockchain.

It serves a small [gRPC](https://grpc.io) API which the node's RPC component uses to submit new transactions. In turn,
the `block-producer` uses the store's gRPC API to submit blocks and query chain state.

For more information on the installation and operation of this component, please see the [node's readme](../../README.md).

## API

The full gRPC API can be found [here](../../proto/proto/block_producer.proto).

---

### SubmitProvenTx

Submits a proven transaction to the block-producer, returning the current chain height if successful.

The block-producer does _not_ verify the transaction's proof as it assumes the RPC component has done so. This is done
to minimize the performance impact of new transactions on the block-producer.

Transactions are verified before being added to the block-producer's mempool. Transaction which fail verification are
rejected and an error is returned. Possible reasons for verification failure include

- current account state does not match the transaction's initial account state
- transaction attempts to consume non-existing, or already consumed notes
- transaction attempts to create a duplicate note
- invalid transaction proof (checked by the RPC component)

Verified transactions are added to the mempool however they are still _not guaranteed_ to make it into a block.
Transactions may be evicted from the mempool if their preconditions no longer hold. Currently the only precondition is
transaction expiration height. Furthermore, as a defense against bugs the mempool may evict transactions it deems buggy
e.g. cause block proofs to fail due to some bug in the VM, compiler, prover etc.

Since transactions can depend on other transactions in the mempool this means a specific transaction may be evicted if:

- it's own expiration height is exceeded, or
- it is deemed buggy by the mempool, or
- any ancestor transaction in the mempool is evicted

This list will be extended in the future e.g. eviction due to gas price fluctuations.

Note that since the RPC response only indicates admission into the mempool, its not directly possible to know if the
transaction was evicted. The best way to ensure this is to effectively add a timeout to the transaction by setting the
transaction's expiration height. Once the blockchain advances beyond this point without including the transaction you
can know for certain it was evicted.

---

## Crate Features

- `tracing-forest`: sets logging using tracing-forest. Disabled by default.

## License
This project is [MIT licensed](../../LICENSE).
