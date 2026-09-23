#!/usr/bin/env bash
set -euo pipefail

# Runs the ntx-builder large-account harness end to end:
#
#   1. seeds a counter account with a large storage map, plus the wallet that owns it
#   2. measures that account in isolation, with no network running
#   3. brings up a local network with the pair committed at genesis, via run-node.sh
#   4. submits one increment and asserts the counter advances
#
# Environment:
#   MAP_ENTRIES   entries in the counter's storage map (default 1000)
#   RUN_OFFLINE   set to 0 to skip the isolated measurements
#   WORK_DIR      where seeded accounts, the genesis config, and logs go (default a temp dir)
#   WAIT_BLOCKS   blocks to allow for the counter to advance (default 20)
#   SKIP_BUILD    set to 1 to reuse existing release binaries
#   KEEP          set to 1 to leave WORK_DIR and the running stack in place on success
#   VERBOSE       set to 1 to also stream every step's output
#
# Note: run-node.sh removes and recreates /tmp/{node,validator-*,ntx-builder,genesis,accounts} and
# kills whatever holds its ports, so do not run this alongside another local stack.

MAP_ENTRIES="${MAP_ENTRIES:-1000}"
WAIT_BLOCKS="${WAIT_BLOCKS:-20}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KEEP="${KEEP:-0}"
RUN_OFFLINE="${RUN_OFFLINE:-1}"
VERBOSE="${VERBOSE:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK_DIR="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/large-account-harness.XXXXXX")}"
mkdir -p "$WORK_DIR"
SEEDED_DIR="$WORK_DIR/seeded"
ACCOUNTS_CONFIG_FILE="$WORK_DIR/accounts.toml"
BUILD_LOG="$WORK_DIR/build.log"
SEED_LOG="$WORK_DIR/seed.log"
OFFLINE_OUT="$WORK_DIR/offline.out"
STACK_LOG="$WORK_DIR/stack.log"
VERIFY_OUT="$WORK_DIR/verify.out"

RPC_PORT=57291
NTX_BUILDER_PORT=50301
# Must match run-node.sh's validator keys.
VALIDATOR_1_KEY_HEX="0101010101010101010101010101010101010101010101010101010101010101"
VALIDATOR_2_KEY_HEX="0202020202020202020202020202020202020202020202020202020202020202"

BIN_DIR="$REPO_ROOT/target/release"
BENCH_BIN="$BIN_DIR/miden-large-account-benchmark"
VALIDATOR_BIN="$BIN_DIR/miden-validator"

STACK_PID=""
SAMPLER_PID=""
STOP_SAMPLING="$WORK_DIR/.stop-sampling"
NTX_RSS_FILE="$WORK_DIR/ntx-builder.rss"
NODE_RSS_FILE="$WORK_DIR/node.rss"

# The log to show if the run fails, set as each phase begins.
FAILURE_LOG=""

phase() {
    FAILURE_LOG="${2:-}"
    printf '\n%s\n' "$1"
}

# Runs a command with its output captured to $1, streaming it too when VERBOSE=1.
quietly() {
    local log="$1"
    shift

    if [[ "$VERBOSE" == "1" ]]; then
        "$@" 2>&1 | tee "$log"
    else
        "$@" > "$log" 2>&1
    fi
}

# Formats a byte count in the largest unit that stays readable.
human_bytes() {
    awk -v b="$1" 'BEGIN {
        if (b >= 1073741824)   printf "%.1f GiB", b / 1073741824;
        else if (b >= 1048576) printf "%.1f MiB", b / 1048576;
        else if (b >= 1024)    printf "%.1f KiB", b / 1024;
        else                   printf "%d B", b;
    }'
}

# Tracks the peak resident set size of the processes matching $1, writing the running maximum (in
# KiB, summed across matches) to $2 until STOP_SAMPLING appears.
#
# Sampling from outside is deliberate: it measures what the real service holds, without needing any
# instrumentation inside the node or the ntx-builder.
sample_peak_rss() {
    local pattern="$1" out="$2" max=0 total rss pids

    echo 0 > "$out"
    while [[ ! -f "$STOP_SAMPLING" ]]; do
        total=0
        pids=$(pgrep -f "$pattern" 2>/dev/null || true)
        for pid in $pids; do
            rss=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || true)
            if [[ -n "$rss" ]]; then
                total=$((total + rss))
            fi
        done
        if [[ "$total" -gt "$max" ]]; then
            max=$total
            echo "$max" > "$out"
        fi
        sleep 0.5
    done
}

cleanup() {
    local status=$?

    touch "$STOP_SAMPLING" 2>/dev/null || true
    if [[ -n "$SAMPLER_PID" ]]; then
        wait "$SAMPLER_PID" 2>/dev/null || true
    fi

    if [[ -n "$STACK_PID" ]] && kill -0 "$STACK_PID" 2>/dev/null; then
        if [[ "$KEEP" == "1" && $status -eq 0 ]]; then
            printf '\nStack left running (KEEP=1), pid %s. Stop it with: kill %s\n' \
                "$STACK_PID" "$STACK_PID"
            echo "Seeded accounts: $SEEDED_DIR"
            return
        fi
        kill -TERM "$STACK_PID" 2>/dev/null || true
        wait "$STACK_PID" 2>/dev/null || true
    fi

    if [[ $status -ne 0 ]]; then
        printf '\nFAILED\n'
        if [[ -n "$FAILURE_LOG" && -s "$FAILURE_LOG" ]]; then
            printf '\n--- %s (last 30 lines) ---\n' "$FAILURE_LOG"
            tail -n 30 "$FAILURE_LOG"
        fi
        # The stack log usually holds the real cause even when another step reported the failure.
        if [[ -s "$STACK_LOG" && "$FAILURE_LOG" != "$STACK_LOG" ]]; then
            printf '\n--- %s (errors) ---\n' "$STACK_LOG"
            grep -iE "error|panic" "$STACK_LOG" | tail -n 10 || echo "(none)"
        fi
        printf '\nLogs: %s\n' "$WORK_DIR"
    elif [[ "$KEEP" != "1" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# --- build ---------------------------------------------------------------------------------------

if [[ "$SKIP_BUILD" != "1" ]]; then
    phase "Building release binaries" "$BUILD_LOG"
    quietly "$BUILD_LOG" cargo build --release \
        -p miden-large-account-benchmark \
        -p miden-node \
        -p miden-validator \
        -p miden-ntx-builder \
        -p miden-remote-prover
fi

for bin in "$BENCH_BIN" "$VALIDATOR_BIN" "$BIN_DIR/miden-node" \
    "$BIN_DIR/miden-ntx-builder" "$BIN_DIR/miden-remote-prover"; do
    [[ -x "$bin" ]] || { echo "error: missing binary $bin (run without SKIP_BUILD=1)" >&2; exit 1; }
done

# --- seed ----------------------------------------------------------------------------------------

phase "Seeding the faucet + wallet + counter set ($MAP_ENTRIES map entries)" "$SEED_LOG"
quietly "$SEED_LOG" "$BENCH_BIN" seed \
    --output-dir "$SEEDED_DIR" --counter-map-entries "$MAP_ENTRIES"

COUNTER_SIZE=$(wc -c < "$SEEDED_DIR/counter.mac" | tr -d ' ')
WALLET_SIZE=$(wc -c < "$SEEDED_DIR/wallet.mac" | tr -d ' ')

# --- isolated measurements -----------------------------------------------------------------------

if [[ "$RUN_OFFLINE" == "1" ]]; then
    phase "Measuring the account in isolation (no network)" "$OFFLINE_OUT"
    quietly "$OFFLINE_OUT" cargo bench --quiet \
        -p miden-ntx-builder --bench large_account -- "$MAP_ENTRIES"
fi

# --- network -------------------------------------------------------------------------------------

cat > "$ACCOUNTS_CONFIG_FILE" <<EOF
[[account]]
name = "counter"
path = "$SEEDED_DIR/counter.mac"
EOF

phase "Starting the local network" "$STACK_LOG"
STACK_START_EPOCH=$(date +%s)
ACCOUNTS_CONFIG="$ACCOUNTS_CONFIG_FILE" \
MIDEN_VALIDATOR_GENESIS_NATIVE_FAUCET="$SEEDED_DIR/faucet.mac" \
MIDEN_VALIDATOR_GENESIS_FUNDING_ACCOUNT="$SEEDED_DIR/wallet.mac" \
MIDEN_VALIDATOR_GENESIS_VERIFICATION_BASE_FEE=0 \
ENABLE_FULL_NODES=false \
MIDEN_NODE_BIN="$BIN_DIR/miden-node" \
MIDEN_VALIDATOR_BIN="$VALIDATOR_BIN" \
MIDEN_NTX_BUILDER_BIN="$BIN_DIR/miden-ntx-builder" \
MIDEN_REMOTE_PROVER_BIN="$BIN_DIR/miden-remote-prover" \
    ./scripts/run-node.sh > "$STACK_LOG" 2>&1 &
STACK_PID=$!

for _ in $(seq 1 180); do
    if ! kill -0 "$STACK_PID" 2>/dev/null; then
        echo "error: the stack exited during startup" >&2
        exit 1
    fi
    # Both must be up: the ntx-builder connects to the sequencer while starting and exits if
    # refused, so a dead builder would otherwise surface later as the counter never advancing.
    if nc -z 127.0.0.1 "$RPC_PORT" 2>/dev/null && nc -z 127.0.0.1 "$NTX_BUILDER_PORT" 2>/dev/null
    then
        break
    fi
    sleep 1
done

if ! nc -z 127.0.0.1 "$RPC_PORT" 2>/dev/null; then
    echo "error: the sequencer's RPC never came up on :$RPC_PORT" >&2
    exit 1
fi
if ! nc -z 127.0.0.1 "$NTX_BUILDER_PORT" 2>/dev/null; then
    echo "error: the ntx-builder never came up on :$NTX_BUILDER_PORT" >&2
    exit 1
fi

STACK_READY_SECS=$(( $(date +%s) - STACK_START_EPOCH ))

# Sample from here on, so the peak covers the ntx-builder loading the account and building the
# network transaction.
sample_peak_rss "miden-ntx-builder start" "$NTX_RSS_FILE" &
SAMPLER_PID=$!
sample_peak_rss "miden-node sequencer" "$NODE_RSS_FILE" &

# The ports bind before the first block is produced; give the sequencer a moment so the genesis
# handshake and encryption-key fetch have something to talk to.
sleep 5

# --- verify --------------------------------------------------------------------------------------

VALIDATOR_1_PUBKEY=$("$VALIDATOR_BIN" pubkey --signing-key.hex "$VALIDATOR_1_KEY_HEX")
VALIDATOR_2_PUBKEY=$("$VALIDATOR_BIN" pubkey --signing-key.hex "$VALIDATOR_2_KEY_HEX")

phase "Submitting an increment and waiting for the counter to advance" "$VERIFY_OUT"
quietly "$VERIFY_OUT" "$BENCH_BIN" verify \
    --accounts-dir "$SEEDED_DIR" \
    --rpc-url "http://127.0.0.1:$RPC_PORT" \
    --validator-signing-public-key "$VALIDATOR_1_PUBKEY" \
    --validator-signing-public-key "$VALIDATOR_2_PUBKEY" \
    --wait-blocks "$WAIT_BLOCKS"

# --- results -------------------------------------------------------------------------------------

touch "$STOP_SAMPLING"
sleep 1

NTX_PEAK_KIB=$(cat "$NTX_RSS_FILE" 2>/dev/null || echo 0)
NODE_PEAK_KIB=$(cat "$NODE_RSS_FILE" 2>/dev/null || echo 0)
PROVING=$(sed -n 's/.*proved in \([0-9.]*\)s.*/\1/p' "$VERIFY_OUT" | head -1)
BLOCKS=$(sed -n 's/.*after \([0-9]*\) blocks.*/\1/p' "$VERIFY_OUT" | head -1)
PER_ENTRY=$(( MAP_ENTRIES > 0 ? COUNTER_SIZE / MAP_ENTRIES : 0 ))

# Pull the isolated figures out of the benchmark's fixed-width table row for this size.
ISOLATED_RESIDENT=""
if [[ -s "$OFFLINE_OUT" ]]; then
    # Each value is "number unit", so the fields are separated with a character that cannot appear
    # inside them — splitting on whitespace would break them apart.
    IFS='|' read -r ISOLATED_RESIDENT ISOLATED_PEAK ISOLATED_LOAD < <(
        awk -v n="$MAP_ENTRIES" -v OFS='|' \
            '$1 == n { print $2" "$3, $4" "$5, $8" "$9; exit }' "$OFFLINE_OUT"
    ) || true
fi

printf '\nPASS — the ntx-builder loaded the account and consumed the network note\n'
printf '\n%s map entries\n' "$MAP_ENTRIES"
printf '  %-24s %s (%s/entry)\n' "counter on disk" \
    "$(human_bytes "$COUNTER_SIZE")" "$(human_bytes "$PER_ENTRY")"
printf '  %-24s %s\n' "wallet on disk" "$(human_bytes "$WALLET_SIZE")"

if [[ -n "$ISOLATED_RESIDENT" ]]; then
    printf '  %-24s %s resident, %s peak, %s to load\n' "account in isolation" \
        "$ISOLATED_RESIDENT" "$ISOLATED_PEAK" "$ISOLATED_LOAD"
fi

printf '  %-24s %s\n' "ntx-builder peak RSS" "$(human_bytes $((NTX_PEAK_KIB * 1024)))"
printf '  %-24s %s\n' "sequencer peak RSS" "$(human_bytes $((NODE_PEAK_KIB * 1024)))"
printf '  %-24s %ss ready, %ss proving, %s blocks to consume\n' "timings" \
    "$STACK_READY_SECS" "${PROVING:-?}" "${BLOCKS:-?}"
printf '\nIsolated figures are exact; RSS is whole-process, sampled at 0.5s, so a floor.\n'
