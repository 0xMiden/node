#!/usr/bin/env bash
set -euo pipefail

# Configuration
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-false}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
BINARY="${MIDEN_NODE_BIN:-./target/debug/miden-node}"
VALIDATOR_BINARY="${MIDEN_VALIDATOR_BIN:-./target/debug/miden-validator}"
NTX_BUILDER_BINARY="${MIDEN_NTX_BUILDER_BIN:-./target/debug/miden-ntx-builder}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
if [[ -n "$KMS_KEY_ID" ]]; then
    AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set when KMS_KEY_ID is set}"
    export AWS_REGION
fi

GENESIS_CONFIG="crates/store/src/genesis/config/samples/01-simple.toml"
SEQUENCER_DIR="/tmp/sequencer"
STORE_REPLICA_1_DIR="/tmp/store-replica-1"
STORE_REPLICA_2_DIR="/tmp/store-replica-2"
VALIDATOR_DIR="/tmp/validator"
NTX_BUILDER_DIR="/tmp/ntx-builder"
ACCOUNTS_DIR="/tmp/accounts"

# Sequencer (store + block-producer + rpc) exposes four endpoints.
SEQUENCER_RPC_PORT=57291
SEQUENCER_BLOCK_PRODUCER_PORT=50201
SEQUENCER_NTX_BUILDER_PORT=50002
SEQUENCER_REPLICA_PORT=50001

# Replica stores expose only the RPC API.
STORE_REPLICA_1_RPC_PORT=50011
STORE_REPLICA_2_RPC_PORT=50021

VALIDATOR_PORT=50101
NTX_BUILDER_PORT=50301

# RPC servers backed by replica stores.
RPC_REPLICA_1_PORT=57292
RPC_REPLICA_2_PORT=57293

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

PORTS=(
    $SEQUENCER_RPC_PORT
    $SEQUENCER_BLOCK_PRODUCER_PORT
    $SEQUENCER_NTX_BUILDER_PORT
    $SEQUENCER_REPLICA_PORT
    $STORE_REPLICA_1_RPC_PORT
    $STORE_REPLICA_2_RPC_PORT
    $VALIDATOR_PORT
    $NTX_BUILDER_PORT
    $RPC_REPLICA_1_PORT
    $RPC_REPLICA_2_PORT
)
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

    rm -rf "$VALIDATOR_DIR" "$ACCOUNTS_DIR" "$SEQUENCER_DIR" \
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

    echo "Bootstrapping sequencer..."
    $BINARY sequencer bootstrap \
        --data-directory "$SEQUENCER_DIR" \
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

# The sequencer runs store + block-producer + rpc in a single process and exposes four endpoints:
#   rpc.listen            → client-facing RPC API
#   block-producer.listen → block-producer gRPC API (used by downstream rpc replicas)
#   ntx-builder.listen    → sequencer.NtxBuilderApi gRPC API (used by the standalone ntx-builder binary)
#   replica.listen        → replica.Api gRPC API (used by downstream store replicas)
echo "Starting sequencer..."
OTEL_SERVICE_NAME=miden-sequencer $BINARY sequencer start \
    --rpc.listen "0.0.0.0:$SEQUENCER_RPC_PORT" \
    --block-producer.listen "0.0.0.0:$SEQUENCER_BLOCK_PRODUCER_PORT" \
    --ntx-builder.listen "0.0.0.0:$SEQUENCER_NTX_BUILDER_PORT" \
    --replica.listen "0.0.0.0:$SEQUENCER_REPLICA_PORT" \
    --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
    --data-directory "$SEQUENCER_DIR" \
    $EXTRA_ARGS &
PIDS+=($!)

KMS_START_ARGS=()
if [[ -n "$KMS_KEY_ID" ]]; then
    KMS_START_ARGS+=(--key.kms-id "$KMS_KEY_ID")
fi

echo "Starting validator..."
OTEL_SERVICE_NAME=miden-validator $VALIDATOR_BINARY start --listen "0.0.0.0:$VALIDATOR_PORT" \
    --data-directory "$VALIDATOR_DIR" \
    $EXTRA_ARGS \
    "${KMS_START_ARGS[@]+"${KMS_START_ARGS[@]}"}" &
PIDS+=($!)

# Give sequencer and validator a moment to bind their ports.
sleep 2

# Replica 1 syncs from the sequencer's replica.Api endpoint.
echo "Starting store replica 1 (upstream: sequencer replica at 127.0.0.1:$SEQUENCER_REPLICA_PORT)..."
OTEL_SERVICE_NAME=miden-store-replica-1 $BINARY store start-replica \
    --rpc.listen "0.0.0.0:$STORE_REPLICA_1_RPC_PORT" \
    --upstream-store.url "http://127.0.0.1:$SEQUENCER_REPLICA_PORT" \
    --data-directory "$STORE_REPLICA_1_DIR" \
    $EXTRA_ARGS &
PIDS+=($!)

# Replica 2 syncs from replica 1, proving replicas can act as upstreams.
echo "Starting store replica 2 (upstream: replica 1 at 127.0.0.1:$STORE_REPLICA_1_RPC_PORT)..."
OTEL_SERVICE_NAME=miden-store-replica-2 $BINARY store start-replica \
    --rpc.listen "0.0.0.0:$STORE_REPLICA_2_RPC_PORT" \
    --upstream-store.url "http://127.0.0.1:$STORE_REPLICA_1_RPC_PORT" \
    --data-directory "$STORE_REPLICA_2_DIR" \
    $EXTRA_ARGS &
PIDS+=($!)

# RPC servers backed by replica stores forward writes to the sequencer's block-producer endpoint.
echo "Starting RPC server (replica 1)..."
OTEL_SERVICE_NAME=miden-rpc-replica-1 $BINARY rpc start \
    --listen "0.0.0.0:$RPC_REPLICA_1_PORT" \
    --store.url "http://127.0.0.1:$STORE_REPLICA_1_RPC_PORT" \
    --block-producer.url "http://127.0.0.1:$SEQUENCER_BLOCK_PRODUCER_PORT" \
    --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
    $EXTRA_ARGS &
PIDS+=($!)

echo "Starting RPC server (replica 2)..."
OTEL_SERVICE_NAME=miden-rpc-replica-2 $BINARY rpc start \
    --listen "0.0.0.0:$RPC_REPLICA_2_PORT" \
    --store.url "http://127.0.0.1:$STORE_REPLICA_2_RPC_PORT" \
    --block-producer.url "http://127.0.0.1:$SEQUENCER_BLOCK_PRODUCER_PORT" \
    --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
    $EXTRA_ARGS &
PIDS+=($!)

# The standalone ntx-builder connects to the sequencer's NtxBuilderApi gRPC endpoint.
echo "Starting network transaction builder..."
OTEL_SERVICE_NAME=miden-ntx-builder $NTX_BUILDER_BINARY start \
    --listen "0.0.0.0:$NTX_BUILDER_PORT" \
    --store.url "http://127.0.0.1:$SEQUENCER_NTX_BUILDER_PORT" \
    --block-producer.url "http://127.0.0.1:$SEQUENCER_BLOCK_PRODUCER_PORT" \
    --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
    --data-directory "$NTX_BUILDER_DIR" \
    $EXTRA_ARGS &
PIDS+=($!)

echo "=== All components running. Ctrl+C to stop. ==="
echo "=== Sequencer RPC endpoint: :$SEQUENCER_RPC_PORT ==="
echo "=== Replica RPC endpoints: :$RPC_REPLICA_1_PORT, :$RPC_REPLICA_2_PORT ==="
echo "=== Block propagation chain: sequencer(:$SEQUENCER_REPLICA_PORT) -> replica-1(:$STORE_REPLICA_1_RPC_PORT) -> replica-2(:$STORE_REPLICA_2_RPC_PORT) ==="
wait
