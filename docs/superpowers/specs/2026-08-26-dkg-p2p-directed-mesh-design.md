# Validator DKG P2P Directed Mesh Design

This is a historical design draft. For the current protocol and commands, see the
[validator operator guide](../../external/src/network-operator/validator.md#storage-key-setup).

## Scope

This design replaces the current pair-election handshake with a simpler directed mesh and
extends it into a complete live DKG ceremony.

The live ceremony has no coordinator, board host, or application-level forwarding. Every
validator sends its own protocol messages directly to every other validator. Iroh relays may
still carry an encrypted connection when a direct path is unavailable.

The existing offline/manual DKG remains unchanged while `validator dkg-p2p` is developed.
Networking, DKG execution, persistence, and removal of the offline command remain separate,
reviewable steps.

## Trusted Inputs

`ParticipateOptions::validate` constructs a `Ceremony` only after establishing these
invariants:

- the local validator signing key is present in the genesis validator set;
- the threshold is nonzero and does not exceed the validator count;
- the storage-key epoch is exactly 32 bytes;
- `--peer.endpoint` contains exactly one unique endpoint ID for every other validator;
- the local persistent Iroh endpoint ID is not present in the peer set; and
- the output location is suitable for a newly created ceremony bundle.

Genesis remains the source of truth for validator signing identities. Endpoint IDs are
operator-supplied connection hints until a signed Join message binds each one to a genesis
validator.

For a one-validator genesis, the peer set is empty. The validator still executes both DKG
rounds locally and publishes an ordinary one-of-one storage-key bundle.

## Directed Mesh

Every validator dials every configured peer and simultaneously runs one accept loop. A pair of
validators therefore has two Iroh connections:

- the local outgoing connection is only used to send local messages; and
- the local incoming connection is only used to receive that peer's messages.

Each outgoing connection opens one unidirectional QUIC stream. The stream carries the phase
messages in order: Join, Ready, Deal, and Complete. The corresponding incoming stream is read
in that order. This removes endpoint ordering, dialer election, bidirectional stream roles, and
peer-specific accept routing. Each message is a length-prefixed canonical Miden encoding with a
phase-specific maximum size; the protocol does not allocate an unbounded peer-provided length.

`Ceremony::handshake` starts all outbound connection attempts and the single accept loop
concurrently. An outbound `Endpoint::connect` failure is retried indefinitely with the existing
`miden_node_utils::retry` exponential backoff, jittered between one and thirty seconds. A
successfully established connection is not reconnected: any later transport or protocol
failure aborts the ceremony, and operators start a new ceremony with new ephemeral state.

The accept loop logs the endpoints still missing every thirty seconds. Connections from
endpoint IDs not listed in `--peer.endpoint` are closed and ignored. A malformed Join from a
configured endpoint, a duplicate active connection from that endpoint, or any authenticated
protocol violation aborts the ceremony.

## Join

At ceremony startup, each validator samples one `CeremonyNonce` and generates one ephemeral
Golden identity key and proof of possession. These values are reused for every peer within that
ceremony and discarded afterward.

The common registration is:

```text
ParticipantRegistration {
    validator_public_key,
    endpoint_id,
    ceremony_nonce,
    dkg_identity_public_key,
    dkg_identity_proof,
}
```

The Join message contains:

```text
Join {
    genesis_commitment,
    threshold,
    storage_key_epoch,
    registration,
    receiver_endpoint_id,
    validator_signature,
}
```

The signature covers the canonical serialization of all preceding fields under the domain
`miden-validator-dkg-p2p/join/v1`. Including both endpoint IDs binds the signature to the actual
Iroh connection and prevents replaying the Join to a different endpoint. The protocol uses the
ALPN `miden-validator-dkg-p2p/1`.

For each incoming Join, the receiver checks:

- `connection.remote_id()` equals `registration.endpoint_id`;
- `receiver_endpoint_id` equals the local endpoint ID;
- the configuration fields equal the local validated ceremony configuration;
- the validator public key is a member of the genesis validator set;
- the validator signature is valid;
- the Golden identity proof is valid; and
- neither the endpoint nor validator key has already registered.

After receiving one valid registration from every configured endpoint, the local registration
plus the received registrations must contain every genesis validator exactly once. This check
turns the untrusted endpoint list into an authenticated validator-to-endpoint mapping held by
the `Session`.

Participant indices follow genesis validator order. The Join transcript commitment is a
domain-separated hash of the ceremony configuration and every `ParticipantRegistration` in
that order. The receiver-specific Join field and validator signature are not included, so all
honest validators derive the same transcript. The Golden decryption session ID is derived from
this commitment, and the context session ID is derived from the decryption session ID using the
existing domain-separated derivation. The eVRF setup coefficient remains the existing fixed,
domain-separated value; it is not chosen by a participant.

## Ready Barrier

Once the full Join transcript is known, each validator sends:

```text
Ready {
    session_id,
    join_transcript_commitment,
}
```

It then waits for a matching Ready from every other genesis validator. No Deal message is sent
before this barrier completes. Because every validator sends its view to every other validator,
different registrations or ceremony configurations cause the honest participants to compare
different commitments and abort before DKG messages are generated.

Join signatures authenticate the directed streams. Ready, Deal, and Complete include the
session ID and rely on that stream authentication rather than adding redundant per-message
validator signatures.

## Deal Exchange

After Ready, each validator creates its Golden decryption dealing and zero-secret context
dealing once. The private shares remain local. The two public `DealerMessage` values are encoded
in one canonical message:

```text
Deal {
    session_id,
    decryption_dealing,
    context_dealing,
}
```

Exactly the same serialized Deal bytes are written to every outgoing stream. A validator reads
one Deal from every incoming stream, associates it with the already authenticated validator,
and verifies both dealings with Golden against the common participant registry and DKG
configuration. Missing, duplicate, malformed, invalid, or wrong-session dealings abort the
ceremony.

Each validator combines its local private shares with all verified public dealings using
Golden's `complete` operation for both rounds. The dealing transcript commitment hashes the
session ID and both rounds' public dealings in genesis participant order. The output commitment
hashes the resulting public key set and setup context. Secret shares are never included in a
network message or transcript commitment.

## Persistence And Complete

The local storage-key bundle is written atomically before Complete is sent. This ensures that a
validator never announces completion for an output it has not persisted.

After persistence, each validator sends:

```text
Complete {
    session_id,
    dealing_transcript_commitment,
    output_commitment,
}
```

It waits for matching Complete messages from every other validator. A mismatch or disconnect
aborts the ceremony. If failure occurs after the new output directory was published but before
all Complete messages matched, `Ceremony::complete` removes only that newly created directory so
output from a failed ceremony cannot be used accidentally. `complete` takes ownership of a
`PersistedOutput`, which represents both the published path and the public commitments it must
exchange. There is no resume path.

On success, `Session::close` closes all streams and the Iroh endpoint. The persistent endpoint
secret remains on disk; the ceremony nonce, Golden identity secret, connections, and other
ephemeral state are discarded.

## Command Flow

The command should remain a readable outline of the protocol:

```rust
let ceremony = self.validate().await?;
let mut session = ceremony.handshake().await?;
let output = ceremony.run_dkg(&mut session).await?;
let persisted = ceremony.persist(output).await?;
ceremony.complete(&mut session, persisted).await?;
session.close().await;
```

The Complete step owns failure cleanup. It does not require restart state, a coordinator object,
a generic message router, or a hosted transcript board.

## Code Organization

- `dkg_p2p.rs` defines CLI options and the command-level ceremony outline.
- `dkg_p2p/ceremony.rs` defines validated ceremony data and phase orchestration methods.
- `dkg_p2p/ceremony/handshake.rs` establishes the directed mesh, authenticates Join messages,
  and completes the Ready barrier.
- `dkg_p2p/ceremony/dkg.rs` creates, exchanges, verifies, and completes Golden dealings.
- `dkg_p2p/ceremony/complete.rs` computes commitments and performs the Complete exchange.
- Persistence uses the existing storage-key bundle representations where they match the live
  output, without importing the offline manifest/coordinator workflow.

Protocol types stay private to their phase module unless another phase genuinely consumes
them. Shared types are introduced only where this implementation creates actual duplication.

## Verification

Tests use real local Iroh endpoints with the minimal discovery configuration. They do not mock
Iroh, retry behavior, cryptographic primitives, or filesystem calls.

Focused protocol tests cover:

- validators starting in different orders and eventually forming the directed mesh;
- a delayed peer being reached through outbound retries;
- unrelated incoming endpoints being ignored without blocking configured peers;
- signed Join messages binding both the sender and receiver endpoint IDs;
- the endpoint registrations resolving to exactly the genesis validator set;
- Ready detecting different Join transcript commitments;
- both dealings being verified and associated with the authenticated sender;
- Complete detecting transcript or public-output disagreement; and
- a one-of-one ceremony producing a valid ordinary storage-key bundle.

An end-to-end local test runs a small multi-validator ceremony and checks that every output has
the same public key set and setup context while each validator receives its own valid secret
share. Codec tests cover only protocol-owned serialization boundaries.
