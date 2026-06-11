# Oddities and FAQs

Common questions and head scratchers.

## Chain MMR

The chain MMR always lags behind the blockchain by one block because otherwise there would be a cyclic dependency
between the chain MMR and the block hash:

- chain MMR contains each block's hash as a leaf
- block hash calculation includes the chain MMR's root

To work-around this the inclusion of a block hash in the chain MMR is delayed by one block. Or put differently, block
`N` is responsible for inserting block `N-1` into the chain MMR. This does _not_ break blockchain linkage because
the block header (and therefore hash) still includes the previous block's hash.

## Crate: `rocksdb-cxx-linkage-fix`

This crate is used to ensure that statically linking the `rocksdb` library works as intended.

More information can be found in the crate's doc comments, but this crate is required for now to be included
as part of the store crate's `build.rs`, since the store pulls in `rocksdb` (via `miden-crypto`'s
`persistent-forest` feature) when its `rocksdb` feature is enabled.
