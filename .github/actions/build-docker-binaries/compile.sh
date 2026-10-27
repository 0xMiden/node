#!/usr/bin/env bash
set -euo pipefail

# Configures the compiler cache for this container's build and uploads its results.
#
# Keeping this setup in CI lets the Dockerfile build without AWS or kache.
finish() {
    result=$?
    trap - EXIT
    if command -v kache >/dev/null; then
        if [[ "${result}" == 0 && "${CACHE_WRITABLE:-false}" == true ]]; then
            kache save-manifest --manifest-key "${KACHE_MANIFEST_KEY}" --namespace "${KACHE_NAMESPACE}" || result=$?
            kache sync --push || result=$?
        fi
        kache stats --full --format github --output /output/report.md || true
        kache stats --full --format json --output /output/report.json || true
        kache daemon stop || true
    else
        printf 'S3 compiler cache is disabled for this build.\n' > /output/report.md
    fi
    exit "${result}"
}
trap finish EXIT

if command -v kache >/dev/null; then
    cp /run/remote.toml /tmp/kache.toml
    cat >> /tmp/kache.toml <<'TOML'

[cc]
extra_allowlist_flags = ["-fmerge-all-constants", "-mno-omit-leaf-frame-pointer"]
TOML
    export KACHE_CONFIG=/tmp/kache.toml KACHE_CACHE_DIR=/tmp/kache-cache
    export KACHE_RUNTIME_DIR=/tmp/kache-runtime KACHE_BASE_DIR=/app
    export KACHE_MAX_SIZE=50GiB KACHE_CACHE_EXECUTABLES=1
    export RUSTC_WRAPPER=kache CC="kache cc" CXX="kache c++" CC_KNOWN_WRAPPER_CUSTOM=kache
    kache daemon start
    kache doctor
fi
bash scripts/build-container-binaries.sh
