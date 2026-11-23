#!/bin/sh

# These libraries embed MASM packages whose debug info contains absolute source paths.
# Keying them by path lets kache reuse them on CI runners with the same directory layout.
# https://github.com/0xMiden/miden-vm/issues/4250
case "${CARGO_CRATE_NAME:-}" in
    miden_core_lib|miden_standards|miden_agglayer)
        export KACHE_RUSTC_PATH_NORMALIZE=0
        ;;
esac

exec kache "$@"
