#!/usr/bin/env bash
set -euo pipefail

# Builds the release binaries consumed by the runtime images.
#
# Docker and CI use the same command so selecting prebuilt binaries does not
# change the release profile, binary selection, or build environment.
binaries=(
    miden-node miden-validator miden-note-transport miden-ntx-builder
    miden-network-monitor miden-funding-service miden-remote-prover
    miden-benchmark miden-genesis
)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/app/target}"
output_dir="${OUTPUT_DIR:-/app/bin}"

# Removes incomplete registry extractions left by interrupted Cargo downloads.
#
# Cargo cannot repair a cached source directory without its completion marker.
registry="${CARGO_HOME:-/usr/local/cargo}/registry/src"
if [[ -d "${registry}" ]]; then
    find "${registry}" -mindepth 2 -maxdepth 2 -type d \
        '!' -exec test -s '{}/.cargo-ok' ';' -exec rm -rf '{}' +
fi

jobs="${CARGO_BUILD_JOBS:-$(awk -v ncpu="$(nproc)" \
    '/MemTotal/ { j = int($2 / (2 * 1024 * 1024)); if (j < 1) j = 1; if (j > ncpu) j = ncpu; print j }' \
    /proc/meminfo)}"
args=()
for binary in "${binaries[@]}"; do
    args+=(--bin "${binary}")
done
cargo build --release --locked --jobs "${jobs}" "${args[@]}"
mkdir -p "${output_dir}"
for binary in "${binaries[@]}"; do
    cp "${CARGO_TARGET_DIR}/release/${binary}" "${output_dir}/"
done
