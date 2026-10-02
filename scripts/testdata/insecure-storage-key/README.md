# Insecure storage key

These files hold a deterministic **two-of-three** storage key used by the docker-compose network and the benchmark smoke
test to exercise threshold storage.

Layout:

- `validator-<n>/storage-key.bundle`: the complete startup bundle for each participant, including the epoch, shared
  public setup and its private share. Compose stages the matching bundle; the benchmark uses participant 1's bundle.
- `setup-context.wire`, `public-key-set.wire` — the shared public setup, the same for every validator.
- `validator-1/secret-share.wire`, `validator-2/secret-share.wire`, `validator-3/secret-share.wire` — each participant's
  **distinct** secret share. The Compose bootstrap service stages only the matching share in each validator's bundle.
- `secret-share.wire` — participant 1's share (identical to `validator-1/secret-share.wire`), retained for legacy
  tooling.

Every validator must hold a **different** share. Mounting the same share into all three validators makes any 2-of-3
recovery collapse to a single participant, which the combiner rejects — so threshold recovery would silently be
impossible even though each validator stores encrypted records.

This key is public and must not be used outside tests.

Compose checks each staged bundle with `miden-validator dkg validate-fixture --bundle-file <FILE>` before it marks the
local network as bootstrapped. This fixture-only check binds the secret share to its expected participant index.
Production bundles must use `miden-validator dkg validate`, which also checks genesis, the ceremony manifest, and signed
transcript.

## Regenerating

The fixture is derived deterministically by `bin/validator/src/storage_key.rs` (`tests::values_for`). Regenerate it
with:

```sh
cargo test -p miden-validator --lib \
  storage_key::tests::write_insecure_storage_key_fixture -- --ignored
```

Update the embedded bundle bytes in `compose/validator.yml` to match when regenerating these fixtures.
