.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables ------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
BUILD_PROTO=BUILD_PROTO=1
CONTAINER_RUNTIME ?= docker

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Runs Clippy with configs
	cargo clippy --locked --all-targets --all-features --workspace -- -D warnings
	cargo clippy --locked --all-targets --all-features -p miden-remote-prover -- -D warnings
	cargo clippy --locked -p miden-remote-prover-client --target wasm32-unknown-unknown --no-default-features --features batch-prover,block-prover,tx-prover -- -D warnings


.PHONY: fix
fix: ## Runs Fix with configs
	cargo fix --allow-staged --allow-dirty --all-targets --all-features --workspace
	cargo fix --allow-staged --allow-dirty --all-targets --all-features -p miden-remote-prover


.PHONY: format
format: ## Runs Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Runs Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check


.PHONY: machete
machete: ## Runs machete to find unused dependencies
	cargo machete


.PHONY: toml
toml: ## Runs Format for all TOML files
	taplo fmt


.PHONY: toml-check
toml-check: ## Runs Format for all TOML files but only in check mode
	taplo fmt --check --verbose

.PHONY: typos-check
typos-check: ## Runs spellchecker
	typos

.PHONY: workspace-check
workspace-check: ## Runs a check that all packages have `lints.workspace = true`
	cargo workspace-lints


.PHONY: lint
lint: typos-check format fix clippy toml machete ## Runs all linting tasks at once (Clippy, fixing, formatting, machete)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generates & checks documentation
	$(WARNINGS) cargo doc --all-features --keep-going --release --locked

.PHONY: book
book: ## Builds the book & serves documentation site
	mdbook serve --open docs/internal

.PHONY: serve-docs
serve-docs: ## Serves the docs
	cd docs/external && npm run start:dev

# --- testing -------------------------------------------------------------------------------------

.PHONY: test
test:  ## Runs all tests
	cargo nextest run --all-features --workspace

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	${BUILD_PROTO} cargo check --all-features --all-targets --locked --workspace

.PHONY: check-features
check-features: ## Checks all feature combinations compile without warnings using cargo-hack
	@scripts/check-features.sh

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Builds all crates and re-builds protobuf bindings for proto crates
	${BUILD_PROTO} cargo build --locked --workspace
	${BUILD_PROTO} cargo build --locked -p miden-remote-prover-client --target wasm32-unknown-unknown --no-default-features --features batch-prover,block-prover,tx-prover # no-std compatible build

# --- installing ----------------------------------------------------------------------------------

.PHONY: install-node
install-node: ## Installs node
	${BUILD_PROTO} cargo install --path bin/node --locked

.PHONY: install-remote-prover
install-remote-prover: ## Install remote prover's CLI
	$(BUILD_PROTO) cargo install --path bin/remote-prover --bin miden-remote-prover --features concurrent --locked

.PHONY: install-stress-test
install-stress-test: ## Installs stress-test binary
	cargo install --path bin/stress-test --locked

.PHONY: install-network-monitor
install-network-monitor: ## Installs network monitor binary
	cargo install --path bin/network-monitor --locked

# --- docker --------------------------------------------------------------------------------------

.PHONY: docker-build-node
docker-build-node: ## Builds the Miden node using Docker (override with CONTAINER_RUNTIME=podman)
	@CREATED=$$(date) && \
	VERSION=$$(cat bin/node/Cargo.toml | grep -m 1 '^version' | cut -d '"' -f 2) && \
	COMMIT=$$(git rev-parse HEAD) && \
	$(CONTAINER_RUNTIME) build --build-arg CREATED="$$CREATED" \
        		 --build-arg VERSION="$$VERSION" \
          		 --build-arg COMMIT="$$COMMIT" \
                 -f bin/node/Dockerfile \
                 -t miden-node-image .

.PHONY: docker-run-node
docker-run-node: ## Runs the Miden node as a Docker container (override with CONTAINER_RUNTIME=podman)
	$(CONTAINER_RUNTIME) volume create miden-db
	$(CONTAINER_RUNTIME) run --name miden-node \
			   -p 57291:57291 \
               -v miden-db:/db \
               -d miden-node-image

## --- setup --------------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v mdbook        >/dev/null 2>&1 && echo "[OK] mdbook is installed"        || echo "[MISSING] mdbook       (make install-tools)"
	@command -v typos         >/dev/null 2>&1 && echo "[OK] typos is installed"         || echo "[MISSING] typos        (make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] cargo-nextest is installed" || echo "[MISSING] cargo-nextest(make install-tools)"
	@command -v taplo         >/dev/null 2>&1 && echo "[OK] taplo is installed"         || echo "[MISSING] taplo        (make install-tools)"
	@command -v cargo-machete >/dev/null 2>&1 && echo "[OK] cargo-machete is installed" || echo "[MISSING] cargo-machete (make install-tools)"
	@command -v npm >/dev/null 2>&1 && echo "[OK] npm is installed" || echo "[MISSING] npm is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs tools required by the Makefile
	@echo "Installing development tools..."
	# Rust-related
	cargo install mdbook --locked
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-machete --locked
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Node.js not found. Please install Node.js from https://nodejs.org/ or using your package manager"; \
		echo "On macOS: brew install node"; \
		echo "On Ubuntu/Debian: sudo apt install nodejs npm"; \
		echo "On Windows: Download from https://nodejs.org/"; \
		exit 1; \
	fi
	@echo "Development tools installation complete!"
