#!/usr/bin/env bash
set -euo pipefail

# Runs compilation on the native runner and exports only finished binaries.
#
# Credentials and kache enter a disposable container through environment and
# read-only mounts; Docker image layers never contain them.
case "${RUNNER_ARCH}/${ARCHITECTURE}" in
    X64/amd64|ARM64/arm64) ;;
    *) echo "Runner architecture does not match ${ARCHITECTURE}" >&2; exit 1 ;;
esac
output="${RUNNER_TEMP}/docker-binaries"
mkdir -p "${output}/app/bin"
args=(
    --rm
    --mount "type=bind,src=${GITHUB_WORKSPACE},dst=/app,readonly"
    --mount "type=bind,src=${output},dst=/output"
    --mount "type=bind,src=${ACTION_PATH}/compile.sh,dst=/run/compile.sh,readonly"
    -e CARGO_TARGET_DIR=/tmp/target
    -e OUTPUT_DIR=/output/app/bin
)
if [[ -n "${RUSTC_WRAPPER:-}" ]]; then
    args+=(
        --mount "type=bind,src=${RUSTC_WRAPPER},dst=/usr/local/bin/kache,readonly"
        --mount "type=bind,src=${RUSTC_WRAPPER%/*}/kache-engine,dst=/usr/local/bin/kache-engine,readonly"
        -e CACHE_WRITABLE -e KACHE_R2_ENDPOINT -e KACHE_S3_ACCESS_KEY -e KACHE_S3_SECRET_KEY
        -e KACHE_PULL_REQUEST_PREFIX
        -e GITHUB_ACTIONS -e GITHUB_EVENT_NAME -e GITHUB_REF_TYPE -e GITHUB_REF_PROTECTED
        -e KACHE_GITHUB_SCHEDULE_WRITES="${CACHE_WRITABLE}"
        -e KACHE_MANIFEST_KEY="node-docker-${ARCHITECTURE}"
        -e KACHE_NAMESPACE="node-docker-${ARCHITECTURE}"
    )
fi
docker run "${args[@]}" node-ci-build-env bash /run/compile.sh
echo "context=${output}" >> "${GITHUB_OUTPUT}"
