# Validator Component

The validator is responsible for verifying each new block and signing it if correct.

This signature is required _before_ a block may be committed on chain, and thus acts as an
independent safe guard.

The validator is therefore run completely separate from the main node operations, and is operated
by a separate entity. The validator's public key is published (or at least will be for `mainnet`).

## Dual purpose: training wheels

The validator has a 2nd purpose while Miden is maturing. To prevent private state from being lost, and to guard
from potential bugs in the VM/cryptography primitives, Miden will launch with training wheels. Notably, we
require users to _include_ the private input data along with their transactions. This means users will have privacy
on the _network_ but not from the validator set.

As part of the transaction submission process, each transaction, its proof, and private inputs, are sent to the validator,
which re-executes the transaction, thereby verifying it and its proof are correct. This also lets us store the private data
as part of our training wheels.

## Block verification

The validator ensures that each new block is sequential with the previously signed block. i.e. `header.parent_commitment == last_block.commitment`.
It also checks that the block contains only transactions that it has previously seen and verified.

Once verified, the block is signed and returned to the sender.

## Transaction encryption key

In addition to its per-validator signing key, every validator is provisioned with the _same_
shared transaction encryption keypair, an Ed25519 key that miden-crypto uses for X25519 key
agreement in its IES scheme. Clients use it to encrypt the private transaction inputs they
submit, so that any validator in the set can decrypt them.

The `GetTransactionEncryptionKey` endpoint returns the shared public key together with an IES
scheme identifier, an opaque key ID, and a list of validator attestations, currently holding one
signature from this validator's own signing key over an attestation commitment (the
`TransactionEncryptionKey` proto message documents the exact payload). The commitment carries a domain tag that separates attestations from block header
signatures, and the genesis commitment so an attestation cannot replay across networks. The
signature proves to clients that a chain-recognized validator vouches for the key, so the key can
be served through an untrusted RPC.

This scheme does not protect the inputs from parties holding the shared secret and has no forward
secrecy. It is the first phase of the transaction input encryption design: later phases move the
key material to threshold and TEE-managed setups.

### Submission path

`SubmitProvenTransaction` carries a `SealedTransactionInputs` envelope: a `key_id` in the clear plus
the ciphertext of a serialized `SealedMessage`. The validator rebuilds the associated data from its
_own_ scheme, key id and genesis commitment, plus the transaction id it parses from the accompanying
plaintext `ProvenTransaction`. Nothing the submitter controls enters the associated data, so a
mismatched `key_id` cannot influence which key is tried: it only lets the validator answer
`failed_precondition` ("re-fetch the key") instead of an indistinguishable authentication failure.

The unseal happens before the serve lock is taken, so a slow or hung decrypt backend cannot starve
the exclusive lock that a backup block subscription needs. The cost is that an already-validated
resubmission pays for the unseal before being short-circuited.

After the proof, re-execution, and header checks pass, the validator encrypts the effects of the
re-executed transaction under a fresh content key. Golden EHTDH1 protects that content key with the
validators' threshold key. The validator stores only the transaction ID and the protected record. It
does not store the client envelope or plaintext. A rejected transaction never creates a record.

The record holds a `TransactionEffects` message in its canonical Protobuf encoding. The effects
state what the transaction did: the account state commitments, the account patch, the input and
output notes, the reference block, and the expiration block. They omit the partial account, the
partial blockchain, the advice witness, and the transaction arguments, so a record is evidence of a
transaction rather than a means to execute it again. A record names its own format in
`format_version`, and both encryption layers authenticate that version.

Only format version 1 is supported. Validator databases created with the transaction inputs schema
must be recreated. There is no migration for those databases.
