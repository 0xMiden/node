#!/usr/bin/env bash
set -euo pipefail

# Configuration
BINARY="./target/debug/miden-node"
GENESIS_CONFIG="crates/store/src/genesis/config/samples/01-simple.toml"
KMS_KEY_ID="${KMS_KEY_ID:?error: KMS_KEY_ID environment variable must be set}"

STORE_DIR="/tmp/store"
VALIDATOR_DIR="/tmp/validator"
NTX_BUILDER_DIR="/tmp/ntx-builder"
ACCOUNTS_DIR="/tmp/accounts"

AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set}"
export AWS_REGION

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

# --- Bootstrap ---

echo "=== Bootstrapping ==="

rm -rf "$VALIDATOR_DIR" "$ACCOUNTS_DIR" "$STORE_DIR" "$NTX_BUILDER_DIR"

echo "Bootstrapping validator..."
$BINARY validator bootstrap \
    --data-directory "$VALIDATOR_DIR" \
    --genesis-block-directory "$VALIDATOR_DIR" \
    --accounts-directory "$ACCOUNTS_DIR" \
    --genesis-config-file "$GENESIS_CONFIG" \
    --validator.key.kms-id "$KMS_KEY_ID"

echo "Bootstrapping store..."
$BINARY store bootstrap \
    --data-directory "$STORE_DIR" \
    --genesis-block "$VALIDATOR_DIR/genesis.dat"

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

echo "Starting validator..."
$BINARY validator start "$VALIDATOR_URL" \
    --enable-otel \
    --data-directory "$VALIDATOR_DIR" \
    --key.kms-id "$KMS_KEY_ID" &
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
