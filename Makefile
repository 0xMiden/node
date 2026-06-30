.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables ------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
STRESS_TEST_DATA_DIR ?= stress-test-store-$(shell date +%Y%m%d-%H%M%S)
COMPOSE_FILES = -f docker-compose.yml -f compose/telemetry.yml -f compose/monitor.yml
DOCKER_PLATFORM ?=
DOCKER_PLATFORM_ARG = $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM),)
DOCKER_VERSION ?= $(shell awk -F '"' '/^version[[:space:]]*=/ { print $$2; exit }' Cargo.toml)
CONFIG_DIR = .config
EXISTING_TRACKED_FILES = while IFS= read -r file; do [ -f "$$file" ] && printf '%s\n' "$$file"; done
README_FILES = $(shell git ls-files '*README.md' | $(EXISTING_TRACKED_FILES))
EXTERNAL_DOCS_MARKDOWN_FILES = $(shell git ls-files 'docs/external/**/*.md' | $(EXISTING_TRACKED_FILES))
MARKDOWN_FILES = $(README_FILES) $(EXTERNAL_DOCS_MARKDOWN_FILES)
PRETTIER_CONFIG = $(CONFIG_DIR)/prettier.json
PRETTIER_LOG_LEVEL = warn
PRETTIER_VERSION ?= 3.8.3
MARKDOWNLINT_CONFIG = $(CONFIG_DIR)/markdownlint-cli2.yaml
MARKDOWNLINT_CLI2_VERSION ?= 0.22.1
CSPELL_CONFIG = $(CONFIG_DIR)/cspell.yaml
CSPELL_VERSION ?= 10.0.1
RUSTFMT_CONFIG = $(CONFIG_DIR)/rustfmt.toml
TAPLO_CONFIG = $(CONFIG_DIR)/taplo.toml

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
format: markdown-format ## Runs rustfmt, README formatting, and comment reflow
	cargo xtask fmt-comments --write --rustfmt-config $(RUSTFMT_CONFIG)
	cargo +nightly fmt --all -- --config-path $(RUSTFMT_CONFIG)


.PHONY: format-check
format-check: markdown-format-check ## Checks rustfmt, README formatting, and comment reflow
	cargo xtask fmt-comments --check --rustfmt-config $(RUSTFMT_CONFIG)
	cargo +nightly fmt --all --check -- --config-path $(RUSTFMT_CONFIG)


.PHONY: markdown-format
markdown-format: ## Formats Markdown files
	@prettier --config $(PRETTIER_CONFIG) --log-level $(PRETTIER_LOG_LEVEL) --write $(MARKDOWN_FILES)


.PHONY: markdown-format-check
markdown-format-check: ## Checks Markdown formatting
	@prettier --config $(PRETTIER_CONFIG) --log-level $(PRETTIER_LOG_LEVEL) --check $(MARKDOWN_FILES)


.PHONY: markdown-lint
markdown-lint: ## Lints Markdown files
	markdownlint-cli2 --config $(MARKDOWNLINT_CONFIG) $(MARKDOWN_FILES)


.PHONY: markdown-spellcheck
markdown-spellcheck: ## Spellchecks Markdown files
	cspell --config $(CSPELL_CONFIG) --no-progress --show-suggestions $(MARKDOWN_FILES)


.PHONY: shear
shear: ## Runs cargo-shear to find unused or misplaced dependencies
	cargo shear --check-test-targets --deny-warnings


.PHONY: toml
toml: ## Runs Format for all TOML files
	taplo fmt --config $(TAPLO_CONFIG)


.PHONY: toml-check
toml-check: ## Runs Format for all TOML files but only in check mode
	taplo fmt --config $(TAPLO_CONFIG) --check --verbose

.PHONY: typos-check
typos-check: ## Runs spellchecker
	typos

.PHONY: workspace-check
workspace-check: ## Runs a check that all packages have `lints.workspace = true`
	cargo workspace-lints


.PHONY: lint
lint: typos-check markdown-spellcheck format markdown-lint fix clippy toml shear ## Runs all linting tasks at once (Clippy, formatting, spelling, Markdown, cargo-shear)

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

.PHONY: install-ntx-builder
install-ntx-builder: ## Installs ntx-builder
	cargo install --path bin/ntx-builder --locked

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

.PHONY: local-network-build
local-network-build: docker-build ## Builds Docker images used by the local development network

.PHONY: local-network-up
local-network-up: ## Starts the local development network
	docker compose $(COMPOSE_FILES) up -d

.PHONY: local-network-down
local-network-down: ## Stops the local development network, preserving volumes
	docker compose $(COMPOSE_FILES) down --remove-orphans

.PHONY: local-network-delete
local-network-delete: ## Stops the local development network and deletes volumes
	docker compose $(COMPOSE_FILES) down -v --remove-orphans

.PHONY: local-network-logs
local-network-logs: ## Follows logs for the local development network
	docker compose $(COMPOSE_FILES) logs -f

.PHONY: docker-build
docker-build: docker-build-node docker-build-validator docker-build-ntx-builder docker-build-monitor docker-build-remote-prover ## Builds all Docker images

.PHONY: docker-build-node
docker-build-node: ## Builds the Miden node using Docker
	@CREATED=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
	VERSION="$(DOCKER_VERSION)" && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --pull $(DOCKER_PLATFORM_ARG) \
                 --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-node \
                 --build-arg PORT=57291 \
                 -t miden-node .

.PHONY: docker-build-validator
docker-build-validator: ## Builds the Miden validator using Docker
	@CREATED=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
	VERSION="$(DOCKER_VERSION)" && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --pull $(DOCKER_PLATFORM_ARG) \
                 --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-validator \
                 --build-arg PORT=50101 \
                 -t miden-validator .

.PHONY: docker-build-ntx-builder
docker-build-ntx-builder: ## Builds the Miden network transaction builder using Docker
	@CREATED=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
	VERSION="$(DOCKER_VERSION)" && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --pull $(DOCKER_PLATFORM_ARG) \
                 --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-ntx-builder \
                 --build-arg PORT=50301 \
                 -t miden-ntx-builder .

.PHONY: docker-build-monitor
docker-build-monitor: ## Builds the network monitor using Docker
	@CREATED=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
	VERSION="$(DOCKER_VERSION)" && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --pull $(DOCKER_PLATFORM_ARG) \
                 --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-network-monitor \
                 --build-arg PORT=3000 \
                 -t miden-network-monitor .

.PHONY: docker-build-remote-prover
docker-build-remote-prover: ## Builds the remote prover using Docker
	@CREATED=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') && \
	VERSION="$(DOCKER_VERSION)" && \
	COMMIT=$$(git rev-parse HEAD) && \
	docker build --pull $(DOCKER_PLATFORM_ARG) \
                 --build-arg CREATED="$$CREATED" \
                 --build-arg VERSION="$$VERSION" \
                 --build-arg COMMIT="$$COMMIT" \
                 --build-arg BIN=miden-remote-prover \
                 --build-arg PORT=50051 \
                 -t miden-remote-prover .

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
	@command -v prettier >/dev/null 2>&1 && echo "[OK] prettier is installed" || echo "[MISSING] prettier is not installed (run: make install-tools)"
	@command -v markdownlint-cli2 >/dev/null 2>&1 && echo "[OK] markdownlint-cli2 is installed" || echo "[MISSING] markdownlint-cli2 is not installed (run: make install-tools)"
	@command -v cspell >/dev/null 2>&1 && echo "[OK] cspell is installed" || echo "[MISSING] cspell is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs tools required by the Makefile
	@echo "Installing development tools..."
	# Rust-related
	cargo install mdbook --locked
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-shear --version 1.12.4 --locked
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Node.js not found. Please install Node.js from https://nodejs.org/ or using your package manager"; \
		echo "On macOS: brew install node"; \
		echo "On Ubuntu/Debian: sudo apt install nodejs npm"; \
		echo "On Windows: Download from https://nodejs.org/"; \
		exit 1; \
	fi
	npm install --global prettier@$(PRETTIER_VERSION) markdownlint-cli2@$(MARKDOWNLINT_CLI2_VERSION) cspell@$(CSPELL_VERSION)
	@echo "Development tools installation complete!"
