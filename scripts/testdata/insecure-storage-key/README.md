# Insecure storage key

These files hold a deterministic **two-of-three** storage key used by the docker-compose network and the benchmark smoke
test to exercise threshold storage.

Layout:

- `validator-<n>/storage-key.bundle`: the complete startup bundle for each participant, including the epoch, shared
  public setup and its private share. Compose stages the matching bundle; the benchmark uses participant 1's bundle.

Every validator must hold a **different** share. Mounting the same share into all three validators makes any 2-of-3
recovery collapse to a single participant, which the combiner rejects — so threshold recovery would silently be
impossible even though each validator stores encrypted records.

This key is public and must not be used outside tests.

Compose checks each staged bundle with `miden-validator dkg validate-fixture --bundle-file <FILE>` before it marks the
local network as bootstrapped. This fixture-only check binds the secret share to its expected participant index.
Production bundles must come from a successful `miden-validator dkg participate` ceremony. That ceremony authenticates
peers against their configured validator keys and confirms matching transcript and public output commitments before it
reports success.

## Regenerating

The fixture is derived deterministically by `bin/validator/src/storage_key.rs` (`tests::values_for`). Regenerate it
with:

```sh
cargo test -p miden-validator --lib \
  storage_key::tests::write_insecure_storage_key_fixture -- --ignored
```

Update the embedded bundle bytes in `compose/validator.yml` to match when regenerating these fixtures.
