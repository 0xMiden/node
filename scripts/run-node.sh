#!/usr/bin/env bash
set -euo pipefail

# Configuration
SKIP_BOOTSTRAP="${SKIP_BOOTSTRAP:-false}"
ENABLE_FULL_NODES="${ENABLE_FULL_NODES:-true}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
# Shared secret authorizing the ntx-builder to submit network transactions to the sequencer's RPC.
# Must match on both the sequencer (--rpc.network-tx-auth-header-value) and the ntx-builder
# (--rpc.auth-header-value), otherwise network transactions are rejected with
# "Network transactions may not be submitted by users yet".
NETWORK_TX_AUTH="${NETWORK_TX_AUTH:-local-dev-ntx-secret}"
NODE_BINARY="${MIDEN_NODE_BIN:-./target/debug/miden-node}"
VALIDATOR_BINARY="${MIDEN_VALIDATOR_BIN:-./target/debug/miden-validator}"
NTX_BUILDER_BINARY="${MIDEN_NTX_BUILDER_BIN:-./target/debug/miden-ntx-builder}"
REMOTE_PROVER_BINARY="${MIDEN_REMOTE_PROVER_BIN:-./target/debug/miden-remote-prover}"
KMS_KEY_ID="${KMS_KEY_ID:-}"
if [[ -n "$KMS_KEY_ID" ]]; then
    AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set when KMS_KEY_ID is set}"
    export AWS_REGION
fi

GENESIS_CONFIG="crates/store/src/genesis/config/samples/01-simple.toml"
NODE_DIR="/tmp/node"
FULL_NODE_1_DIR="/tmp/full-node-1"
FULL_NODE_2_DIR="/tmp/full-node-2"
VALIDATOR_DIR="/tmp/validator"
NTX_BUILDER_DIR="/tmp/ntx-builder"
ACCOUNTS_DIR="/tmp/accounts"

VALIDATOR_PORT=50101
TRUSTED_PORT=50201
NTX_BUILDER_PORT=50301
RPC_PORT=57291
FULL_NODE_1_RPC_PORT=57292
FULL_NODE_2_RPC_PORT=57293
REMOTE_PROVER_PORT=50051

PIDS=()

cleanup() {
    echo "Shutting down..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait "${PIDS[@]}" 2>/dev/null || true
    echo "All components stopped."
}
trap cleanup EXIT INT TERM

kill_ports() {
    local ports=("$VALIDATOR_PORT" "$TRUSTED_PORT" "$NTX_BUILDER_PORT" "$RPC_PORT" "$REMOTE_PROVER_PORT")

    if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
        ports+=("$FULL_NODE_1_RPC_PORT" "$FULL_NODE_2_RPC_PORT")
    fi

    echo "=== Killing processes on required ports ==="
    for port in "${ports[@]}"; do
        pids=$(lsof -ti :"$port" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                echo "Killing PID $pid on port $port"
                kill -9 "$pid" 2>/dev/null || true
            done
        fi
    done
    sleep 1
}

bootstrap_node_data_dir() {
    local label="$1"
    local data_dir="$2"

    echo "Bootstrapping $label..."
    "$NODE_BINARY" bootstrap \
        --data-directory "$data_dir" \
        --file "$VALIDATOR_DIR/genesis.dat"
}

bootstrap_ntx_builder() {
    echo "Bootstrapping network transaction builder..."

    "$NTX_BUILDER_BINARY" bootstrap \
        --data-directory "$NTX_BUILDER_DIR" \
        --file "$VALIDATOR_DIR/genesis.dat"
}

node_resource_attributes() {
    local instance_id="$1"

    if [[ -n "${OTEL_RESOURCE_ATTRIBUTES:-}" ]]; then
        printf "service.instance.id=%s,%s" "$instance_id" "$OTEL_RESOURCE_ATTRIBUTES"
    else
        printf "service.instance.id=%s" "$instance_id"
    fi
}

# --- Kill processes on required ports ---

kill_ports

# --- Bootstrap ---

if [[ "$SKIP_BOOTSTRAP" != "true" ]]; then
    echo "=== Bootstrapping ==="

    rm -rf "$VALIDATOR_DIR" "$ACCOUNTS_DIR" "$NODE_DIR" "$FULL_NODE_1_DIR" "$FULL_NODE_2_DIR" "$NTX_BUILDER_DIR"

    echo "Bootstrapping validator..."
    KMS_BOOTSTRAP_ARGS=()
    if [[ -n "$KMS_KEY_ID" ]]; then
        KMS_BOOTSTRAP_ARGS+=(--key.kms-id "$KMS_KEY_ID")
    fi

    "$VALIDATOR_BINARY" bootstrap \
        --data-directory "$VALIDATOR_DIR" \
        --genesis-block-directory "$VALIDATOR_DIR" \
        --accounts-directory "$ACCOUNTS_DIR" \
        --genesis-config-file "$GENESIS_CONFIG" \
        "${KMS_BOOTSTRAP_ARGS[@]+"${KMS_BOOTSTRAP_ARGS[@]}"}"

    bootstrap_node_data_dir "sequencer node" "$NODE_DIR"
    bootstrap_ntx_builder

    if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
        bootstrap_node_data_dir "full node 1" "$FULL_NODE_1_DIR"
        bootstrap_node_data_dir "full node 2" "$FULL_NODE_2_DIR"
    fi
else
    echo "=== Skipping bootstrap (SKIP_BOOTSTRAP=true) ==="
fi

# --- Start components ---

echo "=== Starting components ==="

KMS_START_ARGS=()
if [[ -n "$KMS_KEY_ID" ]]; then
    KMS_START_ARGS+=(--key.kms-id "$KMS_KEY_ID")
fi

echo "Starting validator..."
"$VALIDATOR_BINARY" start --listen "0.0.0.0:$VALIDATOR_PORT" \
    --data-directory "$VALIDATOR_DIR" \
    $EXTRA_ARGS \
    "${KMS_START_ARGS[@]+"${KMS_START_ARGS[@]}"}" &
PIDS+=($!)

# Give the validator a moment to bind before the sequencer starts producing blocks.
sleep 2

echo "Starting sequencer..."
OTEL_RESOURCE_ATTRIBUTES="$(node_resource_attributes sequencer)" \
    "$NODE_BINARY" sequencer \
    --rpc.listen "0.0.0.0:$RPC_PORT" \
    --rpc.network-tx-auth-header-value "$NETWORK_TX_AUTH" \
    --data-directory "$NODE_DIR" \
    --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
    --ntx-builder.url "http://127.0.0.1:$NTX_BUILDER_PORT" \
    --trusted.listen "0.0.0.0:$TRUSTED_PORT" \
    $EXTRA_ARGS &
PIDS+=($!)

echo "Starting remote prover..."
"$REMOTE_PROVER_BINARY" \
    --kind=transaction \
    --port="$REMOTE_PROVER_PORT" &
PIDS+=($!)

# Give the sequencer a moment to bind before starting the NTX builder
sleep 2

echo "Starting network transaction builder..."
"$NTX_BUILDER_BINARY" start \
    --listen "0.0.0.0:$NTX_BUILDER_PORT" \
    --rpc.url "http://127.0.0.1:$RPC_PORT" \
    --rpc.auth-header-value "$NETWORK_TX_AUTH" \
    --data-directory "$NTX_BUILDER_DIR" \
    --tx-prover.url "http://127.0.0.1:$REMOTE_PROVER_PORT" \
    $EXTRA_ARGS &
PIDS+=($!)

if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
    echo "Starting full node 1 (trusted; upstream: sequencer at 127.0.0.1:$RPC_PORT)..."
    OTEL_RESOURCE_ATTRIBUTES="$(node_resource_attributes full-node-1)" \
        "$NODE_BINARY" full \
        --rpc.listen "0.0.0.0:$FULL_NODE_1_RPC_PORT" \
        --sync.block-source.url "http://127.0.0.1:$RPC_PORT" \
        --data-directory "$FULL_NODE_1_DIR" \
        --validator.url "http://127.0.0.1:$VALIDATOR_PORT" \
        --sequencer.url "http://127.0.0.1:$TRUSTED_PORT" \
        $EXTRA_ARGS &
    PIDS+=($!)

    # Give full node 1 a moment to bind before full node 2 uses it as an upstream.
    sleep 2

    echo "Starting full node 2 (upstream: full node 1 at 127.0.0.1:$FULL_NODE_1_RPC_PORT)..."
    OTEL_RESOURCE_ATTRIBUTES="$(node_resource_attributes full-node-2)" \
        "$NODE_BINARY" full \
        --rpc.listen "0.0.0.0:$FULL_NODE_2_RPC_PORT" \
        --sync.block-source.url "http://127.0.0.1:$FULL_NODE_1_RPC_PORT" \
        --data-directory "$FULL_NODE_2_DIR" \
        $EXTRA_ARGS &
    PIDS+=($!)
else
    echo "=== Full nodes disabled (ENABLE_FULL_NODES=false) ==="
fi

echo "=== All components running. Ctrl+C to stop. ==="
echo "=== Sequencer trusted submission endpoint: :$TRUSTED_PORT ==="
if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
    echo "=== Block propagation chain: :$RPC_PORT -> :$FULL_NODE_1_RPC_PORT -> :$FULL_NODE_2_RPC_PORT ==="
    echo "=== RPC endpoints: :$RPC_PORT, :$FULL_NODE_1_RPC_PORT (trusted submitter), :$FULL_NODE_2_RPC_PORT ==="
else
    echo "=== RPC endpoint: :$RPC_PORT ==="
fi
wait
