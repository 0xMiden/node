#!/usr/bin/env bash
# Local end-to-end benchmark runner.
#
# Bootstraps a fresh validator + node + ntx-builder, starts the stack plus a
# local transaction remote-prover, runs `miden-benchmark create-proofs` then
# `miden-benchmark run-benchmark`, and tears the stack down on exit.
#
# The node is a single process run in `sequencer` mode (store + block-producer
# + public RPC combined). The ntx-builder and validator remain separate
# processes. The ntx-builder requires a transaction prover, so a local
# `miden-remote-prover --kind transaction` is always started; `USE_REMOTE_PROVER`
# additionally offloads the benchmark's `create-proofs` proving to that prover.
#
# Assumes these binaries are on $PATH (install with `make install-node`,
# `make install-validator`, `make install-ntx-builder`,
# `make install-remote-prover`, `make install-benchmark`):
#   - miden-node
#   - miden-validator
#   - miden-ntx-builder
#   - miden-remote-prover
#   - miden-benchmark
#
# Usage:
#   scripts/bench-local.sh                       # 5 tx pairs, local prover
#   N_TXS=20 scripts/bench-local.sh              # 20 tx pairs
#   USE_REMOTE_PROVER=1 scripts/bench-local.sh   # offload create-proofs to the remote-prover
#
# Logs land in ./bench-local-run/logs/. Data lives in ./bench-local-run/data/.

set -euo pipefail

# --- knobs --------------------------------------------------------------------
N_TXS="${N_TXS:-5}"
USE_REMOTE_PROVER="${USE_REMOTE_PROVER:-0}"
CONCURRENCY="${CONCURRENCY:-8}"
WAIT_BLOCKS="${WAIT_BLOCKS:-30}"
RUN_DIR="${RUN_DIR:-./bench-local-run}"

# --- ports --------------------------------------------------------------------
VALIDATOR_PORT=50101
RPC_PORT=57291
NTX_PORT=50301
REMOTE_PROVER_PORT=50051

# --- paths --------------------------------------------------------------------
DATA="$RUN_DIR/data"
LOGS="$RUN_DIR/logs"
PIDS="$RUN_DIR/pids"

mkdir -p "$DATA" "$LOGS" "$PIDS"

# --- helpers ------------------------------------------------------------------
say() { printf "\n\033[1;36m[bench-local] %s\033[0m\n" "$*"; }
die() { printf "\n\033[1;31m[bench-local] %s\033[0m\n" "$*" >&2; exit 1; }

cleanup() {
    say "tearing down..."
    for pidfile in "$PIDS"/*.pid; do
        [ -f "$pidfile" ] || continue
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    sleep 1
    for pidfile in "$PIDS"/*.pid; do
        [ -f "$pidfile" ] || continue
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pidfile"
    done
}
trap cleanup EXIT INT TERM

start_bg() {
    local name="$1"; shift
    say "starting $name"
    ( "$@" ) > "$LOGS/$name.log" 2>&1 &
    echo $! > "$PIDS/$name.pid"
}

wait_for_port() {
    local port="$1" label="$2" tries="${3:-60}"
    for _ in $(seq 1 "$tries"); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    die "$label did not come up on port $port within ${tries}s (see $LOGS/$label.log)"
}

# --- preflight ----------------------------------------------------------------
required_bins=(miden-node miden-validator miden-ntx-builder miden-remote-prover miden-benchmark)
for bin in "${required_bins[@]}"; do
    command -v "$bin" >/dev/null || die "$bin not on PATH"
done

if [ -e "$DATA/node" ] || [ -e "$DATA/validator" ] || [ -e "$DATA/genesis" ] \
    || [ -e "$DATA/ntx-builder" ]; then
    say "wiping previous data dir $DATA"
    rm -rf "$DATA"
    mkdir -p "$DATA"
fi
rm -f "$LOGS"/*.log "$PIDS"/*.pid

GENESIS_FILE="$DATA/genesis/genesis.dat"

# --- bootstrap ----------------------------------------------------------------
say "bootstrapping validator (creates genesis block)"
miden-validator bootstrap \
    --data-directory          "$DATA/validator" \
    --genesis-block-directory "$DATA/genesis" \
    --accounts-directory      "$DATA/accounts" \
    > "$LOGS/bootstrap-validator.log" 2>&1

say "bootstrapping node storage from genesis"
miden-node bootstrap \
    --data-directory "$DATA/node" \
    --file           "$GENESIS_FILE" \
    > "$LOGS/bootstrap-node.log" 2>&1

say "bootstrapping ntx-builder storage from genesis"
miden-ntx-builder bootstrap \
    --data-directory "$DATA/ntx-builder" \
    --file           "$GENESIS_FILE" \
    > "$LOGS/bootstrap-ntx-builder.log" 2>&1

# --- start stack --------------------------------------------------------------
# Topology: validator + transaction prover come up first, then the node
# (sequencer = store + block-producer + RPC), then the ntx-builder which talks
# back to the node's RPC. The sequencer references the ntx-builder URL up front
# but tolerates it not being up yet (gRPC clients connect lazily).
start_bg validator miden-validator start \
    --listen         "127.0.0.1:$VALIDATOR_PORT" \
    --data-directory "$DATA/validator"
wait_for_port "$VALIDATOR_PORT" validator

# The ntx-builder always needs a transaction prover, so start one regardless of
# USE_REMOTE_PROVER (which only governs whether create-proofs offloads here too).
start_bg remote-prover miden-remote-prover \
    --port     "$REMOTE_PROVER_PORT" \
    --kind     transaction \
    --capacity 32 \
    --timeout  300s
wait_for_port "$REMOTE_PROVER_PORT" remote-prover

start_bg node miden-node sequencer \
    --data-directory                            "$DATA/node" \
    --rpc.listen                                "127.0.0.1:$RPC_PORT" \
    --validator.url                             "http://127.0.0.1:$VALIDATOR_PORT" \
    --ntx-builder.url                           "http://127.0.0.1:$NTX_PORT" \
    --batch.max-txs                             64 \
    --block.max-batches                         16 \
    --block.interval                            2s \
    --batch.interval                            500ms \
    --batch.workers                             4 \
    --mempool.tx-capacity                       100000 \
    --rpc.grpc.timeout                          24h \
    --rpc.grpc.max-connection-age               24h \
    --rpc.rate-limit.burst-size                 100000 \
    --rpc.rate-limit.replenish-per-second       100000 \
    --rpc.rate-limit.max-concurrent-connections 1000000
wait_for_port "$RPC_PORT" node

start_bg ntx-builder miden-ntx-builder start \
    --listen         "127.0.0.1:$NTX_PORT" \
    --rpc.url        "http://127.0.0.1:$RPC_PORT" \
    --tx-prover.url  "http://127.0.0.1:$REMOTE_PROVER_PORT" \
    --data-directory "$DATA/ntx-builder"
wait_for_port "$NTX_PORT" ntx-builder

# Using a plain string (not an array) so an empty value expands to nothing
# under `set -u` on bash 3.2 (macOS default). The URL contains no whitespace,
# so word-splitting on `$REMOTE_PROVER_ARG` is safe.
REMOTE_PROVER_ARG=""
if [ "$USE_REMOTE_PROVER" = "1" ]; then
    REMOTE_PROVER_ARG="--remote-prover-url http://127.0.0.1:$REMOTE_PROVER_PORT"
fi

# --- benchmark ----------------------------------------------------------------
say "running create-proofs with N=$N_TXS (use_remote_prover=$USE_REMOTE_PROVER)"
# shellcheck disable=SC2086 # intentional word-splitting on REMOTE_PROVER_ARG
miden-benchmark create-proofs \
    --rpc-url          "http://127.0.0.1:$RPC_PORT" \
    --num-transactions "$N_TXS" \
    $REMOTE_PROVER_ARG \
    2>&1 | tee "$LOGS/create-proofs.log"

say "running run-benchmark"
miden-benchmark run-benchmark \
    --rpc-url     "http://127.0.0.1:$RPC_PORT" \
    --concurrency "$CONCURRENCY" \
    --wait-blocks "$WAIT_BLOCKS" \
    2>&1 | tee "$LOGS/run-benchmark.log"

say "done. logs in $LOGS/"
