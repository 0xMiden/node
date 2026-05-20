.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables ------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
STRESS_TEST_DATA_DIR ?= stress-test-store-$(shell date +%Y%m%d-%H%M%S)
COMPOSE_FILES = -f docker-compose.yml -f compose/telemetry.yml -f compose/monitor.yml

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
format: ## Runs rustfmt and comment reflow
	cargo xtask fmt-comments --write
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Checks rustfmt and comment reflow
	cargo xtask fmt-comments --check
	cargo +nightly fmt --all --check


.PHONY: shear
shear: ## Runs cargo-shear to find unused or misplaced dependencies
	cargo shear


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
lint: typos-check format fix clippy toml shear ## Runs all linting tasks at once (Clippy, fixing, formatting, cargo-shear)

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
	cargo check --all-features --all-targets --locked --workspace

.PHONY: check-features
check-features: ## Checks all feature combinations compile without warnings using cargo-hack
	@scripts/check-features.sh

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Builds all crates and re-builds protobuf bindings for proto crates
	cargo build --locked --workspace
	cargo build --locked -p miden-remote-prover-client --target wasm32-unknown-unknown --no-default-features --features batch-prover,block-prover,tx-prover # no-std compatible build

# --- installing ----------------------------------------------------------------------------------

.PHONY: install-node
install-node: ## Installs node
	cargo install --path bin/node --locked

.PHONY: install-validator
install-validator: ## Installs validator
	cargo install --path bin/validator --locked

.PHONY: install-remote-prover
install-remote-prover: ## Install remote prover's CLI
	cargo install --path bin/remote-prover --bin miden-remote-prover --locked

.PHONY: stress-test-smoke
stress-test: ## Runs stress-test benchmarks
	cargo build --release --locked -p miden-node-stress-test
	@mkdir -p $(STRESS_TEST_DATA_DIR)
	./target/release/miden-node-stress-test seed-store --data-directory $(STRESS_TEST_DATA_DIR) --num-accounts 500 --public-accounts-percentage 50
	./target/release/miden-node-stress-test benchmark-store --data-directory $(STRESS_TEST_DATA_DIR) --iterations 10 --concurrency 1 sync-state
	./target/release/miden-node-stress-test benchmark-store --data-directory $(STRESS_TEST_DATA_DIR) --iterations 10 --concurrency 1 sync-notes
	./target/release/miden-node-stress-test benchmark-store --data-directory $(STRESS_TEST_DATA_DIR) --iterations 10 --concurrency 1 sync-nullifiers --prefixes 10

.PHONY: install-stress-test
install-stress-test: ## Installs stress-test binary
	cargo install --path bin/stress-test --locked

.PHONY: install-network-monitor
install-network-monitor: ## Installs network monitor binary
	cargo install --path bin/network-monitor --locked

.PHONY: install-benchmark
install-benchmark: ## Installs the benchmark binary
	cargo install --path bin/benchmark --locked

# --- docker --------------------------------------------------------------------------------------

.PHONY: compose-genesis
compose-genesis: ## Wipes node volumes and creates a fresh genesis block
	docker compose $(COMPOSE_FILES) down --volumes --remove-orphans
	docker volume rm -f miden-node_node-data
	docker compose $(COMPOSE_FILES) --profile genesis run --rm genesis-store
	docker compose $(COMPOSE_FILES) --profile genesis rm -f

.PHONY: compose-up
compose-up: ## Starts all node components, telemetry, and monitor via docker compose
	docker compose $(COMPOSE_FILES) up -d

.PHONY: compose-down
compose-down: ## Stops and removes all containers via docker compose
	docker compose $(COMPOSE_FILES) down

.PHONY: compose-logs
compose-logs: ## Follows logs for all components via docker compose
	docker compose $(COMPOSE_FILES) logs -f

.PHONY: docker-build
docker-build: docker-build-node docker-build-validator docker-build-ntx-builder docker-build-monitor ## Builds all Docker images

.PHONY: docker-build-node
docker-build-node: ## Builds the Miden node using Docker
	@CREATED=$$(date) && \
	VERSION=$$(cat bin/node/Cargo.toml | grep -m 1 '^version' | cut -d '"' -f 2) && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-node \
                 --build-arg PORT=57291 \
                 -t miden-node .

.PHONY: docker-build-validator
docker-build-validator: ## Builds the Miden validator using Docker
	@CREATED=$$(date) && \
	VERSION=$$(cat bin/validator/Cargo.toml | grep -m 1 '^version' | cut -d '"' -f 2) && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-validator \
                 --build-arg PORT=50101 \
                 -t miden-validator .

.PHONY: docker-build-ntx-builder
docker-build-ntx-builder: ## Builds the Miden network transaction builder using Docker
	@CREATED=$$(date) && \
	VERSION=$$(cat bin/ntx-builder/Cargo.toml | grep -m 1 '^version' | cut -d '"' -f 2) && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-ntx-builder \
                 --build-arg PORT=50301 \
                 -t miden-ntx-builder .

.PHONY: docker-build-monitor
docker-build-monitor: ## Builds the network monitor using Docker
	@CREATED=$$(date) && \
	VERSION=$$(cat bin/network-monitor/Cargo.toml | grep -m 1 '^version' | cut -d '"' -f 2) && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-network-monitor \
                 --build-arg PORT=3000 \
                 -t miden-network-monitor .

.PHONY: docker-run-node
docker-run-node: ## Runs the Miden node as a Docker container
	docker volume create miden-db
	docker run --name miden-node \
			   -p 57291:57291 \
               -v miden-db:/db \
               -d miden-node

## --- setup --------------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v mdbook        >/dev/null 2>&1 && echo "[OK] mdbook is installed"        || echo "[MISSING] mdbook       (make install-tools)"
	@command -v typos         >/dev/null 2>&1 && echo "[OK] typos is installed"         || echo "[MISSING] typos        (make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] cargo-nextest is installed" || echo "[MISSING] cargo-nextest(make install-tools)"
	@command -v taplo         >/dev/null 2>&1 && echo "[OK] taplo is installed"         || echo "[MISSING] taplo        (make install-tools)"
	@command -v cargo-shear >/dev/null 2>&1 && echo "[OK] cargo-shear is installed" || echo "[MISSING] cargo-shear is not installed (run: make install-tools)"
	@command -v npm >/dev/null 2>&1 && echo "[OK] npm is installed" || echo "[MISSING] npm is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs tools required by the Makefile
	@echo "Installing development tools..."
	# Rust-related
	cargo install mdbook --locked
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-shear --version 1.11.2 --locked
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Node.js not found. Please install Node.js from https://nodejs.org/ or using your package manager"; \
		echo "On macOS: brew install node"; \
		echo "On Ubuntu/Debian: sudo apt install nodejs npm"; \
		echo "On Windows: Download from https://nodejs.org/"; \
		exit 1; \
	fi
	@echo "Development tools installation complete!"
