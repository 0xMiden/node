#!/usr/bin/env bash
set -euo pipefail

# Configures the compiler cache for this container's build and uploads its results.
#
# Keeping this setup in CI lets the Dockerfile build without R2 credentials or kache.
#
# A failed upload only warns, so an R2 error or expired credentials never
# fail a build whose binaries compiled.
finish() {
    result=$?
    trap - EXIT
    if command -v kache >/dev/null; then
        if [[ "${result}" == 0 && "${CACHE_WRITABLE:-false}" == true ]]; then
            kache save-manifest --manifest-key "${KACHE_MANIFEST_KEY}" --namespace "${KACHE_NAMESPACE}" \
                || echo "::warning::Failed to save the compiler cache manifest"
            kache sync --push || echo "::warning::Failed to upload compiler cache artifacts"
        fi
        kache stats --full --format github --output /output/report.md || true
        kache stats --full --format json --output /output/report.json || true
        kache daemon stop || true
    else
        printf 'R2 compiler cache is disabled for this build.\n' > /output/report.md
    fi
    exit "${result}"
}
trap finish EXIT

if command -v kache >/dev/null; then
    if [[ "${CACHE_WRITABLE}" != true ]]; then
        export KACHE_REMOTE_READONLY=1
    fi
    cat > /tmp/kache.toml <<TOML
[cache.remote]
type = "s3"
bucket = "kache"
region = "auto"
endpoint = "${KACHE_R2_ENDPOINT}"
prefix = "artifacts"

[cc]
extra_allowlist_flags = ["-fmerge-all-constants", "-mno-omit-leaf-frame-pointer"]
TOML
    export KACHE_CONFIG=/tmp/kache.toml KACHE_CACHE_DIR=/tmp/kache-cache
    export KACHE_RUNTIME_DIR=/tmp/kache-runtime KACHE_BASE_DIR=/app
    export KACHE_MAX_SIZE=50GiB KACHE_CACHE_EXECUTABLES=1
    export RUSTC_WRAPPER=/app/.github/actions/setup-kache/kache.sh
    export CC="kache cc" CXX="kache c++" CC_KNOWN_WRAPPER_CUSTOM=kache
    kache daemon start
    kache doctor
fi
bash scripts/build-container-binaries.sh
