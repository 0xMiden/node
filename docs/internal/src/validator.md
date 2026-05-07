# Validator Component

The validator is responsible for verifying each new block and signing it if correct.

This signature is required _before_ a block may be committed on chain, and thus acts as an
independent safe guard.

The validator is therefore run completely separate from the main node operations, and is operated
by a separate entity. The validator's public key is published (or at least will be for `mainnet`).

## Dual purpose: training wheels

The validator has a 2nd purpose while Miden is maturing. To prevent private state from being lost, and to guard
from potential bugs in the VM/cryptography primitives, Miden will launch with training wheels. Notably, we will
require users to _include_ the private input data along with their transactions. This means users will have privacy
on the _network_ but not from the network operator.

As part of the transaction submission process, each transaction, its proof, and private inputs, are sent to the validator,
which re-executes the transaction, thereby verifying it and its proof are correct. This also lets us store the private data
as part of our training wheels.

## Block verification

The validator ensures that each new block is sequential with the previously signed block. i.e. `header.parent_commitment == last_block.commitment`.
It also checks that the block contains only transactions that it has previously seen and verified.

Once verified, the block is signed and returned to the sender.
