#!/usr/bin/env bash
set -euo pipefail

# Configuration
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-false}"
BINARY="${MIDEN_NODE_BIN:-./target/debug/miden-node}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
if [[ -n "$KMS_KEY_ID" ]]; then
    AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set when KMS_KEY_ID is set}"
    export AWS_REGION
fi

GENESIS_CONFIG="crates/store/src/genesis/config/samples/01-simple.toml"
STORE_DIR="/tmp/store"
VALIDATOR_DIR="/tmp/validator"
NTX_BUILDER_DIR="/tmp/ntx-builder"
ACCOUNTS_DIR="/tmp/accounts"

# Store exposes 3 separate APIs.
STORE_RPC_URL="http://0.0.0.0:50001"
STORE_NTX_BUILDER_URL="http://0.0.0.0:50002"
STORE_BLOCK_PRODUCER_URL="http://0.0.0.0:50003"

VALIDATOR_URL="http://0.0.0.0:50101"
BLOCK_PRODUCER_URL="http://0.0.0.0:50201"
RPC_URL="http://0.0.0.0:57291"

PIDS=()

cleanup() {
    echo "Shutting down..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait
    echo "All components stopped."
}
trap cleanup EXIT INT TERM

# --- Kill processes on required ports ---

PORTS=(50001 50002 50003 50101 50201 57291)
echo "=== Killing processes on required ports ==="
for port in "${PORTS[@]}"; do
    pids=$(lsof -ti :"$port" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        for pid in $pids; do
            echo "Killing PID $pid on port $port"
            kill -9 "$pid" 2>/dev/null || true
        done
    fi
done
sleep 1

# --- Bootstrap ---

if [[ "$SKIP_BOOTSTRAP" != "true" ]]; then
    echo "=== Bootstrapping ==="

    rm -rf "$VALIDATOR_DIR" "$ACCOUNTS_DIR" "$STORE_DIR" "$NTX_BUILDER_DIR"
    mkdir -p "$NTX_BUILDER_DIR"

    echo "Bootstrapping validator..."
    KMS_BOOTSTRAP_ARGS=()
    if [[ -n "$KMS_KEY_ID" ]]; then
        KMS_BOOTSTRAP_ARGS+=(--validator.key.kms-id "$KMS_KEY_ID")
    fi

    $BINARY validator bootstrap \
        --data-directory "$VALIDATOR_DIR" \
        --genesis-block-directory "$VALIDATOR_DIR" \
        --accounts-directory "$ACCOUNTS_DIR" \
        --genesis-config-file "$GENESIS_CONFIG" \
        "${KMS_BOOTSTRAP_ARGS[@]+"${KMS_BOOTSTRAP_ARGS[@]}"}"

    echo "Bootstrapping store..."
    $BINARY store bootstrap \
        --data-directory "$STORE_DIR" \
        --genesis-block "$VALIDATOR_DIR/genesis.dat"
else
    echo "=== Skipping bootstrap (SKIP_BOOTSTRAP=true) ==="
fi

# --- Start components ---

echo "=== Starting components ==="

echo "Starting store..."
$BINARY store start \
    --rpc.url "$STORE_RPC_URL" \
    --ntx-builder.url "$STORE_NTX_BUILDER_URL" \
    --block-producer.url "$STORE_BLOCK_PRODUCER_URL" \
    --data-directory "$STORE_DIR" \
    --enable-otel &
PIDS+=($!)

KMS_START_ARGS=()
if [[ -n "$KMS_KEY_ID" ]]; then
    KMS_START_ARGS+=(--key.kms-id "$KMS_KEY_ID")
fi

echo "Starting validator..."
$BINARY validator start "$VALIDATOR_URL" \
    --enable-otel \
    --data-directory "$VALIDATOR_DIR" \
    "${KMS_START_ARGS[@]+"${KMS_START_ARGS[@]}"}" &
PIDS+=($!)

# Give store and validator a moment to bind their ports.
sleep 2

echo "Starting block producer..."
$BINARY block-producer start "$BLOCK_PRODUCER_URL" \
    --store.url "http://127.0.0.1:50003" \
    --validator.url "http://127.0.0.1:50101" &
PIDS+=($!)

echo "Starting RPC server..."
$BINARY rpc start \
    --url "$RPC_URL" \
    --store.url "http://127.0.0.1:50001" \
    --block-producer.url "http://127.0.0.1:50201" \
    --validator.url "http://127.0.0.1:50101" &
PIDS+=($!)

echo "Starting network transaction builder..."
$BINARY ntx-builder start \
    --store.url "http://127.0.0.1:50002" \
    --block-producer.url "http://127.0.0.1:50201" \
    --validator.url "http://127.0.0.1:50101" \
    --data-directory "$NTX_BUILDER_DIR" &
PIDS+=($!)

echo "=== All components running. Ctrl+C to stop. ==="
wait
