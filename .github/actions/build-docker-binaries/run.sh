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
if [[ "${CACHE_ENABLED}" == true ]]; then
    args+=(
        --mount "type=bind,src=${CACHE_BINARY},dst=/usr/local/bin/kache,readonly"
        --mount "type=bind,src=${CACHE_CONFIG},dst=/run/remote.toml,readonly"
        -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN
        -e AWS_REGION -e AWS_DEFAULT_REGION
        -e GITHUB_ACTIONS -e GITHUB_EVENT_NAME -e GITHUB_REF_TYPE -e GITHUB_REF_PROTECTED
        -e KACHE_MANIFEST_KEY="node-docker-${ARCHITECTURE}"
        -e KACHE_NAMESPACE="node-docker-${ARCHITECTURE}"
    )
fi
docker run "${args[@]}" node-ci-build-env bash /run/compile.sh
echo "context=${output}" >> "${GITHUB_OUTPUT}"
