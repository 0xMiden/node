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
# Runs two validators, hard-coded for local development. Genesis commits both validators' keys
# but is not signed; both must sign every block after genesis, and the sequencer fans block
# signing and transaction submission out to both.
KMS_KEY_ID="${KMS_KEY_ID:-}"
KMS_KEY_ID_2="${KMS_KEY_ID_2:-}"
if [[ -n "$KMS_KEY_ID" || -n "$KMS_KEY_ID_2" ]]; then
    KMS_KEY_ID="${KMS_KEY_ID:?error: KMS_KEY_ID and KMS_KEY_ID_2 must both be set to run two KMS-backed validators}"
    KMS_KEY_ID_2="${KMS_KEY_ID_2:?error: KMS_KEY_ID and KMS_KEY_ID_2 must both be set to run two KMS-backed validators}"
    AWS_REGION="${AWS_REGION:?error: AWS_REGION environment variable must be set when KMS_KEY_ID is set}"
    export AWS_REGION
fi
# Insecure, hard-coded local dev keys used when KMS_KEY_ID is not set. Must be distinct: the
# genesis validator set rejects duplicate keys.
VALIDATOR_1_KEY_HEX="0101010101010101010101010101010101010101010101010101010101010101"
VALIDATOR_2_KEY_HEX="0202020202020202020202020202020202020202020202020202020202020202"
# Insecure, hard-coded local dev shared transaction encryption key. Unlike the signing keys,
# this value must be identical across both validators.
ENCRYPTION_KEY_HEX="0303030303030303030303030303030303030303030303030303030303030303"

# Insecure, hard-coded local dev storage encryption setup.
VALIDATOR_STORAGE_KEY_EPOCH="0909090909090909090909090909090909090909090909090909090909090909"
VALIDATOR_INSECURE_STORAGE_KEY_DIRECTORY="scripts/testdata/insecure-storage-key"
VALIDATOR_INSECURE_STORAGE_KEY_SETUP_CONTEXT="${VALIDATOR_INSECURE_STORAGE_KEY_DIRECTORY}/setup-context.wire"
VALIDATOR_INSECURE_STORAGE_KEY_PUBLIC_KEY_SET="${VALIDATOR_INSECURE_STORAGE_KEY_DIRECTORY}/public-key-set.wire"
VALIDATOR_1_INSECURE_STORAGE_KEY_SECRET_SHARE="${VALIDATOR_INSECURE_STORAGE_KEY_DIRECTORY}/validator-1/secret-share.wire"
VALIDATOR_2_INSECURE_STORAGE_KEY_SECRET_SHARE="${VALIDATOR_INSECURE_STORAGE_KEY_DIRECTORY}/validator-2/secret-share.wire"

GENESIS_CONFIG="${GENESIS_CONFIG:-crates/store/src/genesis/config/samples/01-simple.toml}"
NODE_DIR="/tmp/node"
FULL_NODE_1_DIR="/tmp/full-node-1"
FULL_NODE_2_DIR="/tmp/full-node-2"
VALIDATOR_1_DIR="/tmp/validator-1"
VALIDATOR_2_DIR="/tmp/validator-2"
NTX_BUILDER_DIR="/tmp/ntx-builder"
GENESIS_DIR="/tmp/genesis"
ACCOUNTS_DIR="/tmp/accounts"
BATCH_BUILDER_ACCOUNT_ID_FILE="$GENESIS_DIR/batch-builder-account-id"

VALIDATOR_1_PORT=50101
VALIDATOR_2_PORT=50102
SEQUENCER_INTERNAL_PORT=50201
NTX_BUILDER_PORT=50301
RPC_PORT=57291
FULL_NODE_1_RPC_PORT=57292
FULL_NODE_2_RPC_PORT=57293
REMOTE_PROVER_PORT=50051

PIDS=()

cleanup() {
    echo "Shutting down..."
    if ((${#PIDS[@]})); then
        for pid in "${PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
    echo "All components stopped."
}
trap cleanup EXIT INT TERM

kill_ports() {
    local ports=("$VALIDATOR_1_PORT" "$VALIDATOR_2_PORT" "$SEQUENCER_INTERNAL_PORT" "$NTX_BUILDER_PORT" "$RPC_PORT" "$REMOTE_PROVER_PORT")

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
        --genesis "$GENESIS_DIR/genesis.dat"
}

bootstrap_ntx_builder() {
    echo "Bootstrapping network transaction builder..."

    "$NTX_BUILDER_BINARY" bootstrap \
        --data-directory "$NTX_BUILDER_DIR" \
        --genesis "$GENESIS_DIR/genesis.dat"
}

# Blocks until something is listening on a port, or gives up after roughly $2 seconds.
#
# The ntx-builder connects to the sequencer's RPC during startup and exits if that connection is
# refused, so it must not be started against a fixed sleep: a large genesis state (e.g. an account
# with a big storage map) delays the sequencer's bind well past a couple of seconds.
wait_for_port() {
    local port="$1"
    local timeout="${2:-120}"

    for _ in $(seq 1 "$timeout"); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done

    echo "error: nothing listening on port $port after ${timeout}s" >&2
    return 1
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

    rm -rf "$VALIDATOR_1_DIR" "$VALIDATOR_2_DIR" "$GENESIS_DIR" "$ACCOUNTS_DIR" \
        "$NODE_DIR" "$FULL_NODE_1_DIR" "$FULL_NODE_2_DIR" "$NTX_BUILDER_DIR"

    echo "Building the unsigned genesis block (commits both validators' public keys)..."
    if [[ -n "$KMS_KEY_ID" ]]; then
        VALIDATOR_1_PUBKEY=$("$VALIDATOR_BINARY" pubkey --signing-key.kms-id "$KMS_KEY_ID")
        VALIDATOR_2_PUBKEY=$("$VALIDATOR_BINARY" pubkey --signing-key.kms-id "$KMS_KEY_ID_2")
    else
        VALIDATOR_1_PUBKEY=$("$VALIDATOR_BINARY" pubkey --signing-key.hex "$VALIDATOR_1_KEY_HEX")
        VALIDATOR_2_PUBKEY=$("$VALIDATOR_BINARY" pubkey --signing-key.hex "$VALIDATOR_2_KEY_HEX")
    fi

    GENESIS_OUTPUT=$("$VALIDATOR_BINARY" genesis \
        --genesis-block-directory "$GENESIS_DIR" \
        --accounts-directory "$ACCOUNTS_DIR" \
        --config "$GENESIS_CONFIG" \
        --validator.key "$VALIDATOR_1_PUBKEY" \
        --validator.key "$VALIDATOR_2_PUBKEY")
    printf '%s\n' "$GENESIS_OUTPUT"
    BATCH_BUILDER_ACCOUNT_ID=$(printf '%s\n' "$GENESIS_OUTPUT" | sed -n 's/^Batch builder account id: //p')
    if [[ -z "$BATCH_BUILDER_ACCOUNT_ID" ]]; then
        echo "error: genesis output did not contain the batch builder account id" >&2
        exit 1
    fi
    printf '%s\n' "$BATCH_BUILDER_ACCOUNT_ID" > "$BATCH_BUILDER_ACCOUNT_ID_FILE"

    echo "Bootstrapping validator 1 (seeds from the genesis block)..."
    "$VALIDATOR_BINARY" bootstrap \
        --data-directory "$VALIDATOR_1_DIR" \
        --genesis "$GENESIS_DIR/genesis.dat"

    echo "Bootstrapping validator 2 (seeds from the genesis block)..."
    "$VALIDATOR_BINARY" bootstrap \
        --data-directory "$VALIDATOR_2_DIR" \
        --genesis "$GENESIS_DIR/genesis.dat"

    bootstrap_node_data_dir "sequencer node" "$NODE_DIR"
    bootstrap_ntx_builder

    if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
        bootstrap_node_data_dir "full node 1" "$FULL_NODE_1_DIR"
        bootstrap_node_data_dir "full node 2" "$FULL_NODE_2_DIR"
    fi
else
    echo "=== Skipping bootstrap (SKIP_BOOTSTRAP=true) ==="
fi

if [[ ! -s "$BATCH_BUILDER_ACCOUNT_ID_FILE" ]]; then
    echo "error: batch builder account id is missing; run without SKIP_BOOTSTRAP" >&2
    exit 1
fi
BATCH_BUILDER_ACCOUNT_ID=$(cat "$BATCH_BUILDER_ACCOUNT_ID_FILE")

# --- Start components ---

echo "=== Starting components ==="

KMS_START_ARGS_1=()
KMS_START_ARGS_2=()
if [[ -n "$KMS_KEY_ID" ]]; then
    KMS_START_ARGS_1+=(--signing-key.kms-id "$KMS_KEY_ID")
    KMS_START_ARGS_2+=(--signing-key.kms-id "$KMS_KEY_ID_2")
else
    KMS_START_ARGS_1+=(--signing-key.hex "$VALIDATOR_1_KEY_HEX")
    KMS_START_ARGS_2+=(--signing-key.hex "$VALIDATOR_2_KEY_HEX")
fi

echo "Starting validator 1..."
"$VALIDATOR_BINARY" start --listen "0.0.0.0:$VALIDATOR_1_PORT" \
    --data-directory "$VALIDATOR_1_DIR" \
    --encryption-key.hex "$ENCRYPTION_KEY_HEX" \
    --storage-key.epoch "$VALIDATOR_STORAGE_KEY_EPOCH" \
    --storage-key.setup-context "$VALIDATOR_INSECURE_STORAGE_KEY_SETUP_CONTEXT" \
    --storage-key.public-key-set "$VALIDATOR_INSECURE_STORAGE_KEY_PUBLIC_KEY_SET" \
    --storage-key.secret-share "$VALIDATOR_1_INSECURE_STORAGE_KEY_SECRET_SHARE" \
    $EXTRA_ARGS \
    "${KMS_START_ARGS_1[@]}" &
PIDS+=($!)

echo "Starting validator 2..."
"$VALIDATOR_BINARY" start --listen "0.0.0.0:$VALIDATOR_2_PORT" \
    --data-directory "$VALIDATOR_2_DIR" \
    --encryption-key.hex "$ENCRYPTION_KEY_HEX" \
    --storage-key.epoch "$VALIDATOR_STORAGE_KEY_EPOCH" \
    --storage-key.setup-context "$VALIDATOR_INSECURE_STORAGE_KEY_SETUP_CONTEXT" \
    --storage-key.public-key-set "$VALIDATOR_INSECURE_STORAGE_KEY_PUBLIC_KEY_SET" \
    --storage-key.secret-share "$VALIDATOR_2_INSECURE_STORAGE_KEY_SECRET_SHARE" \
    $EXTRA_ARGS \
    "${KMS_START_ARGS_2[@]}" &
PIDS+=($!)

# Give the validators a moment to bind before the sequencer starts producing blocks.
sleep 2

echo "Starting sequencer..."
OTEL_RESOURCE_ATTRIBUTES="$(node_resource_attributes sequencer)" \
    "$NODE_BINARY" sequencer \
    --rpc.listen "0.0.0.0:$RPC_PORT" \
    --rpc.network-tx-auth-header-value "$NETWORK_TX_AUTH" \
    --data-directory "$NODE_DIR" \
    --validator.url "http://127.0.0.1:$VALIDATOR_1_PORT" \
    --validator.url "http://127.0.0.1:$VALIDATOR_2_PORT" \
    --ntx-builder.url "http://127.0.0.1:$NTX_BUILDER_PORT" \
    --batch.builder.account.id "$BATCH_BUILDER_ACCOUNT_ID" \
    --internal.listen "0.0.0.0:$SEQUENCER_INTERNAL_PORT" \
    $EXTRA_ARGS &
PIDS+=($!)

echo "Starting remote prover..."
"$REMOTE_PROVER_BINARY" \
    --kind=transaction \
    --port="$REMOTE_PROVER_PORT" &
PIDS+=($!)

# The NTX builder connects to the sequencer's RPC while starting up and exits if it is refused, so
# wait for the port rather than sleeping a fixed amount.
echo "Waiting for the sequencer's RPC on :$RPC_PORT before starting the NTX builder..."
wait_for_port "$RPC_PORT"

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
    echo "Starting full node 1 (pre-authenticating; upstream: sequencer at 127.0.0.1:$RPC_PORT)..."
    OTEL_RESOURCE_ATTRIBUTES="$(node_resource_attributes full-node-1)" \
        "$NODE_BINARY" full \
        --rpc.listen "0.0.0.0:$FULL_NODE_1_RPC_PORT" \
        --sync.block-source.url "http://127.0.0.1:$RPC_PORT" \
        --data-directory "$FULL_NODE_1_DIR" \
        --validator.url "http://127.0.0.1:$VALIDATOR_1_PORT" \
        --validator.url "http://127.0.0.1:$VALIDATOR_2_PORT" \
        --sequencer.internal.url "http://127.0.0.1:$SEQUENCER_INTERNAL_PORT" \
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
echo "=== Sequencer internal endpoint: :$SEQUENCER_INTERNAL_PORT ==="
if [[ "$ENABLE_FULL_NODES" == "true" ]]; then
    echo "=== Block propagation chain: :$RPC_PORT -> :$FULL_NODE_1_RPC_PORT -> :$FULL_NODE_2_RPC_PORT ==="
    echo "=== RPC endpoints: :$RPC_PORT, :$FULL_NODE_1_RPC_PORT (pre-authenticated submitter), :$FULL_NODE_2_RPC_PORT ==="
else
    echo "=== RPC endpoint: :$RPC_PORT ==="
fi
wait
