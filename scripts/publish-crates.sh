#!/bin/sh

# Script to publish all miden-node crates to crates.io.
# Usage: ./publish-crates.sh [args]
#
# E.G:   ./publish-crates.sh
#        ./publish-crates.sh --dry-run

set -e

# Check
credentials=~/.cargo/credentials.toml
if [ ! -f "$credentials" ]; then
    red="\033[0;31m"
    echo "${red}WARNING: $credentials not found. See https://doc.rust-lang.org/cargo/reference/publishing.html."
    echo "\033[0m"
fi

# Checkout
echo "Checking out main branch..."
git checkout main
git pull origin main

# Publish
echo "Publishing crates..."
crates=(
miden-node-utils
miden-node-proto-build
miden-node-proto
miden-node-store
miden-remote-prover
miden-remote-prover-client
miden-node-block-producer
miden-node-ntx-producer
miden-node-rpc
miden-node
miden-network-monitor
)
for crate in ${crates[@]}; do
    echo "Publishing $crate..."
    cargo publish -p "$crate" $@
done
