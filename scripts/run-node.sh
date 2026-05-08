#!/usr/bin/env bash
set -euo pipefail

# Configuration
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-false}"
BINARY="${MIDEN_NODE_BIN:-./target/debug/miden-node}"
VALIDATOR_BINARY="${MIDEN_VALIDATOR_BIN:-./target/debug/miden-validator}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
if [[ -n "$KMS_KEY_ID" ]]; then
    AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set when KMS_KEY_ID is set}"
    export AWS_REGION
fi

GENESIS_CONFIG="crates/store/src/genesis/config/samples/01-simple.toml"
STORE_DIR="/tmp/store"
STORE_REPLICA_1_DIR="/tmp/store-replica-1"
STORE_REPLICA_2_DIR="/tmp/store-replica-2"
VALIDATOR_DIR="/tmp/validator"
NTX_BUILDER_DIR="/tmp/ntx-builder"
ACCOUNTS_DIR="/tmp/accounts"

# Primary store (block-producer mode): 3 APIs.
STORE_RPC_URL="http://0.0.0.0:50001"
STORE_NTX_BUILDER_URL="http://0.0.0.0:50002"
STORE_BLOCK_PRODUCER_URL="http://0.0.0.0:50003"

# Replica stores expose only the RPC API (no block-producer or ntx-builder endpoints).
STORE_REPLICA_1_RPC_URL="http://0.0.0.0:50011"
STORE_REPLICA_2_RPC_URL="http://0.0.0.0:50021"

VALIDATOR_URL="http://0.0.0.0:50101"
BLOCK_PRODUCER_URL="http://0.0.0.0:50201"
RPC_URL="http://0.0.0.0:57291"
RPC_REPLICA_1_URL="http://0.0.0.0:57292"
RPC_REPLICA_2_URL="http://0.0.0.0:57293"

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

PORTS=(50001 50002 50003 50011 50021 50101 50201 57291 57292 57293)
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

    rm -rf "$VALIDATOR_DIR" "$ACCOUNTS_DIR" "$STORE_DIR" \
        "$STORE_REPLICA_1_DIR" "$STORE_REPLICA_2_DIR" "$NTX_BUILDER_DIR"
    mkdir -p "$NTX_BUILDER_DIR"

    echo "Bootstrapping validator..."
    KMS_BOOTSTRAP_ARGS=()
    if [[ -n "$KMS_KEY_ID" ]]; then
        KMS_BOOTSTRAP_ARGS+=(--validator.key.kms-id "$KMS_KEY_ID")
    fi

    $VALIDATOR_BINARY bootstrap \
        --data-directory "$VALIDATOR_DIR" \
        --genesis-block-directory "$VALIDATOR_DIR" \
        --accounts-directory "$ACCOUNTS_DIR" \
        --genesis-config-file "$GENESIS_CONFIG" \
        "${KMS_BOOTSTRAP_ARGS[@]+"${KMS_BOOTSTRAP_ARGS[@]}"}"

    echo "Bootstrapping store..."
    $BINARY store bootstrap \
        --data-directory "$STORE_DIR" \
        --genesis-block "$VALIDATOR_DIR/genesis.dat"

    echo "Bootstrapping store replica 1..."
    $BINARY store bootstrap \
        --data-directory "$STORE_REPLICA_1_DIR" \
        --genesis-block "$VALIDATOR_DIR/genesis.dat"

    echo "Bootstrapping store replica 2..."
    $BINARY store bootstrap \
        --data-directory "$STORE_REPLICA_2_DIR" \
        --genesis-block "$VALIDATOR_DIR/genesis.dat"
else
    echo "=== Skipping bootstrap (SKIP_BOOTSTRAP=true) ==="
fi

# --- Start components ---

echo "=== Starting components ==="

echo "Starting store (block-producer mode)..."
$BINARY store start \
    --rpc.url "$STORE_RPC_URL" \
    --ntx-builder.url "$STORE_NTX_BUILDER_URL" \
    --block-producer.url "$STORE_BLOCK_PRODUCER_URL" \
    --data-directory "$STORE_DIR" &
PIDS+=($!)

KMS_START_ARGS=()
if [[ -n "$KMS_KEY_ID" ]]; then
    KMS_START_ARGS+=(--key.kms-id "$KMS_KEY_ID")
fi

echo "Starting validator..."
$VALIDATOR_BINARY start "$VALIDATOR_URL" \
    --data-directory "$VALIDATOR_DIR" \
    "${KMS_START_ARGS[@]+"${KMS_START_ARGS[@]}"}" &
PIDS+=($!)

# Give store and validator a moment to bind their ports.
sleep 2

# Replica 1 syncs from the primary store.
echo "Starting store replica 1 (upstream: primary store at $STORE_RPC_URL)..."
$BINARY store start-replica \
    --rpc.url "$STORE_REPLICA_1_RPC_URL" \
    --upstream-store.url "$STORE_RPC_URL" \
    --data-directory "$STORE_REPLICA_1_DIR" &
PIDS+=($!)

# Replica 2 syncs from replica 1, proving replicas can act as upstreams.
echo "Starting store replica 2 (upstream: replica 1 at $STORE_REPLICA_1_RPC_URL)..."
$BINARY store start-replica \
    --rpc.url "$STORE_REPLICA_2_RPC_URL" \
    --upstream-store.url "$STORE_REPLICA_1_RPC_URL" \
    --data-directory "$STORE_REPLICA_2_DIR" &
PIDS+=($!)

echo "Starting block producer..."
$BINARY block-producer start "$BLOCK_PRODUCER_URL" \
    --store.url "http://127.0.0.1:50003" \
    --validator.url "http://127.0.0.1:50101" &
PIDS+=($!)

echo "Starting RPC server (primary store)..."
$BINARY rpc start \
    --url "$RPC_URL" \
    --store.url "http://127.0.0.1:50001" \
    --block-producer.url "http://127.0.0.1:50201" \
    --validator.url "http://127.0.0.1:50101" &
PIDS+=($!)

echo "Starting RPC server (replica 1)..."
$BINARY rpc start \
    --url "$RPC_REPLICA_1_URL" \
    --store.url "http://127.0.0.1:50011" \
    --block-producer.url "http://127.0.0.1:50201" \
    --validator.url "http://127.0.0.1:50101" &
PIDS+=($!)

echo "Starting RPC server (replica 2)..."
$BINARY rpc start \
    --url "$RPC_REPLICA_2_URL" \
    --store.url "http://127.0.0.1:50021" \
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
echo "=== Block propagation chain: $STORE_RPC_URL -> $STORE_REPLICA_1_RPC_URL -> $STORE_REPLICA_2_RPC_URL ==="
echo "=== RPC endpoints: $RPC_URL, $RPC_REPLICA_1_URL, $RPC_REPLICA_2_URL ==="
wait
