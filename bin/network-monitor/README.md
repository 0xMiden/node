# Miden network monitor

A monitor app for a Miden network's infrastructure.

## Installation

The binary can be installed using the project's Makefile:

```bash
make install-network-monitor
```

## Configuration

The monitor application supports configuration through both command-line arguments and environment variables. Command-line arguments take precedence over environment variables.

### Command-line Arguments

```bash
# View all available options
miden-network-monitor --help

# Common usage examples
miden-network-monitor start --port 8080 --rpc-url http://localhost:50051
miden-network-monitor start --remote-prover-urls http://prover1.com:50052,http://prover2.com:50053
miden-network-monitor start --faucet-url http://localhost:8080 --enable-otel
```

**Available Options:**
- `--rpc-url`: RPC service URL (default: `http://localhost:50051`)
- `--remote-prover-urls`: Comma-separated list of remote prover URLs. If omitted or empty, prover tasks are disabled.
- `--faucet-url`: Faucet service URL for testing. If omitted, faucet testing is disabled.
- `--explorer-url`: Explorer service GraphQL endpoint. If omitted, explorer checks are disabled.
- `--note-transport-url`: Note transport service URL for health checking. If omitted, note transport checks are disabled.
- `--disable-ntx-service`: Disable the network transaction service checks (enabled by default). The network transaction service consists of two components: counter increment (sending increment transactions) and counter tracking (monitoring counter value changes).
- `--remote-prover-test-interval`: Interval at which to test the remote provers services (default: `2m`)
- `--faucet-test-interval`: Interval at which to test the faucet services (default: `2m`)
- `--status-check-interval`: Interval at which to check the status of the services (default: `3s`)
- `--request-timeout`: Timeout for outgoing requests (default: `10s`)
- `--stale-chain-tip-threshold`: Maximum time without a chain tip update before marking RPC as unhealthy (default: `1m`)
- `--port, -p`: Web server port (default: `3000`)
- `--enable-otel`: Enable OpenTelemetry tracing
- `--wallet-filepath`: Path where the wallet account is located (default: `wallet_account.mac`)
- `--counter-filepath`: Path where the network account is located (default: `counter_program.mac`)
- `--counter-increment-interval`: Interval at which to send the increment counter transaction (default: `30s`)
- `--counter-latency-timeout`: Maximum time to wait for a counter update after submitting a transaction (default: `2m`)
- `--help, -h`: Show help information
- `--version, -V`: Show version information

### Environment Variables

If command-line arguments are not provided, the application falls back to environment variables:

- `MIDEN_MONITOR_RPC_URL`: RPC service URL
- `MIDEN_MONITOR_REMOTE_PROVER_URLS`: Comma-separated list of remote prover URLs. If unset or empty, prover tasks are disabled.
- `MIDEN_MONITOR_FAUCET_URL`: Faucet service URL for testing. If unset, faucet testing is disabled.
- `MIDEN_MONITOR_EXPLORER_URL`: Explorer service GraphQL endpoint. If unset, explorer checks are disabled.
- `MIDEN_MONITOR_NOTE_TRANSPORT_URL`: Note transport service URL for health checking. If unset, note transport checks are disabled.
- `MIDEN_MONITOR_DISABLE_NTX_SERVICE`: Set to `true` to disable the network transaction service checks (enabled by default). This affects both counter increment and tracking components.
- `MIDEN_MONITOR_REMOTE_PROVER_TEST_INTERVAL`: Interval at which to test the remote provers services
- `MIDEN_MONITOR_FAUCET_TEST_INTERVAL`: Interval at which to test the faucet services
- `MIDEN_MONITOR_STATUS_CHECK_INTERVAL`: Interval at which to check the status of the services
- `MIDEN_MONITOR_REQUEST_TIMEOUT`: Timeout for outgoing requests
- `MIDEN_MONITOR_STALE_CHAIN_TIP_THRESHOLD`: Maximum time without a chain tip update before marking RPC as unhealthy
- `MIDEN_MONITOR_PORT`: Web server port
- `MIDEN_MONITOR_ENABLE_OTEL`: Enable OpenTelemetry tracing
- `MIDEN_MONITOR_WALLET_FILEPATH`: Path where the wallet account is located
- `MIDEN_MONITOR_COUNTER_FILEPATH`: Path where the network account is located
- `MIDEN_MONITOR_COUNTER_INCREMENT_INTERVAL`: Interval at which to send the increment counter transaction
- `MIDEN_MONITOR_COUNTER_LATENCY_TIMEOUT`: Maximum time to wait for a counter update after submitting a transaction

## Commands

The monitor application supports one main command:

### Start Monitor

Starts the network monitoring service with the web dashboard. RPC status is always enabled. Other tasks are optional and spawn only when configured:

- Prover checks/tests: enabled when `--remote-prover-urls` (or `MIDEN_MONITOR_REMOTE_PROVER_URLS`) is provided
- Faucet testing: enabled when `--faucet-url` (or `MIDEN_MONITOR_FAUCET_URL`) is provided
- Network transaction service: enabled when `--disable-ntx-service=false` or unset (or `MIDEN_MONITOR_DISABLE_NTX_SERVICE=false` or unset)
- Note transport checks: enabled when `--note-transport-url` (or `MIDEN_MONITOR_NOTE_TRANSPORT_URL`) is provided

```bash
# Start with default configuration (RPC only)
miden-network-monitor start

# Start with custom configuration
miden-network-monitor start --port 8080 --rpc-url http://localhost:50051

# Enable network transaction service (both increment and tracking) with custom account file paths
miden-network-monitor start \
  --wallet-filepath my_wallet.mac \
  --counter-filepath my_network_account.mac \
  --rpc-url https://testnet.miden.io:443
```

**Optional Counter Account Management (only when counter is enabled):**
When `--disable-ntx-service=false` or unset, the monitor ensures required network transaction service account exists before starting the task:
1. If file is missing, creates new counter account:
   - Network account with the increment procedure
2. Saves network account to the specified file using the Miden `AccountFile` format
3. Deploys accounts to the network via RPC (if not already deployed)
4. The network account contract authorizes increments only from a whitelisted wallet account

## Usage

### Using Command-line Arguments

```bash
# Single remote prover
miden-network-monitor start --remote-prover-urls http://localhost:50052

# Multiple remote provers and custom configuration
miden-network-monitor start \
  --remote-prover-urls http://localhost:50052,http://localhost:50053,http://localhost:50054 \
  --faucet-url http://localhost:8080 \
  --disable-ntx-service=false \
  --remote-prover-test-interval 2m \
  --faucet-test-interval 2m \
  --status-check-interval 3s \
  --port 8080 \
  --wallet-filepath my_wallet.mac \
  --counter-filepath my_counter.mac \
  --enable-otel

# Get help
miden-network-monitor --help
```

### Using Environment Variables

```bash
# Single remote prover
MIDEN_MONITOR_REMOTE_PROVER_URLS="http://localhost:50052" miden-network-monitor start

# Multiple remote provers, faucet testing, and network transaction service
MIDEN_MONITOR_REMOTE_PROVER_URLS="http://localhost:50052,http://localhost:50053,http://localhost:50054" \
MIDEN_MONITOR_FAUCET_URL="http://localhost:8080" \
MIDEN_MONITOR_WALLET_FILEPATH="my_wallet.mac" \
MIDEN_MONITOR_COUNTER_FILEPATH="my_counter.mac" \
MIDEN_MONITOR_DISABLE_NTX_SERVICE=false \
miden-network-monitor start
```

Once running, the monitor will be available at `http://localhost:3000` (or the configured port).

## Currently Supported Monitor

The monitor application provides real-time status monitoring for the following Miden network components:

### RPC Service
- **Service Health**: Overall RPC service availability and status
- **Stale Chain Tip Detection**: Monitors chain tip progress and marks RPC as unhealthy if the chain tip hasn't changed within the configured threshold (default: 1 minute)
- **Version Information**: RPC service version
- **Genesis Commitment**: Network genesis commitment (with copy-to-clipboard functionality)
- **Store Status**:
  - Store service version and health
  - Chain tip (latest block number)
- **Block Producer Status**:
  - Block producer version and health

### Explorer
- **Service Health**: Explorer availability and freshness of the latest block
- **Latest Block Metadata**:
  - Block height and timestamp
  - Transactions, nullifiers, notes, and account updates counts
  - Block, chain, and proof commitments (shortened display with copy-to-clipboard)
- **Block Delta**: The difference between the explorer's block height and the RPC's chain tip. If the difference is greater than a tolerance, a warning is displayed. This check is performed in the frontend.

### Remote Provers
- **Service Health**: Individual remote prover availability and status  
- **Version Information**: Remote prover service version
- **Supported Proof Types**: Types of proofs the prover can generate (Transaction, Block, Batch)
- **Worker Status**:
  - Individual worker addresses and versions
  - Worker health status (HEALTHY/UNHEALTHY/UNKNOWN)
  - Worker count per prover
- **Proof Generation Testing**: Real-time testing of proof generation capabilities
  - Success rate tracking with test/failure counters
  - Response time measurement for proof generation
  - Proof size monitoring (in KB)
  - Automated testing with mock transactions, blocks, or batches based on supported proof type
  - Combined health status that reflects both connectivity and proof generation capability

### Faucet Service
- **Service Health**: Faucet service availability and token minting capability
- **PoW Challenge Testing**: Real-time proof-of-work challenge solving and token minting
  - Success rate tracking with successful/failed minting attempts
  - Response time measurement for challenge completion
  - Challenge difficulty monitoring
  - Transaction and note ID tracking from successful mints
  - Automated testing on a configurable interval to verify faucet functionality

### Local Transactions (Counter Increment)
- **Service Health**: End-to-end local transaction submission for counter increment
- **Metrics**:
  - Success/Failure counts for increment transactions
  - Last TX ID with copy-to-clipboard
  - Latency in blocks from submission to observed counter update (with pending measurement tracking)

### Network Transactions (Counter Tracking)
- **Service Health**: Real-time monitoring of on-chain counter value changes
- **Metrics**:
  - Current network account counter value (queried from RPC periodically)
  - Expected counter value based on successful increments sent
  - Pending notes: How many transactions are queued/unprocessed
  - Last updated timestamp

### Note Transport
- **Service Health**: Checks the note transport service via the standard gRPC Health Checking Protocol
- **Metrics**:
  - Service URL
  - gRPC serving status (Serving, NotServing, Unknown)

## User Interface

The web dashboard provides a clean, responsive interface with the following features:

- **Real-time Updates**: Automatically refreshes service status every 10 seconds
- **Unified Service Cards**: Each service is displayed in a dedicated card that auto-sizes to show all information
- **Combined Prover Information**: Remote prover cards integrate both connectivity status and proof generation test results
- **Faucet Testing Display**: Shows faucet test results with challenge difficulty and minting success metrics
- **Visual Health Indicators**: Color-coded status indicators and clear success/failure metrics
- **Interactive Elements**: Copy-to-clipboard functionality for genesis commitments, transaction IDs, and note IDs
- **Responsive Design**: Optimized for both desktop and mobile viewing

### gRPC-Web Browser Probe

The dashboard automatically probes RPC and Remote Prover services every 30 seconds using gRPC-Web protocol. This tests whether the browser can successfully communicate with these services.

**What it checks:**
- Browser connectivity to the service endpoint
- CORS configuration (the probe is a real cross-origin request from the browser)
- gRPC-Web protocol handling (proper framing and trailers)
- Basic service availability (calls the `Status` endpoint)

**Results displayed:**
- **gRPC-Web: OK** / **gRPC-Web: FAILED** status
- Response latency in milliseconds
- Error details (if failed)
- Time since last probe

**Common failure scenarios:**
- **CORS / Network error**: The service is not configured to accept cross-origin requests from the browser, or the service is unreachable
- **HTTP 4xx/5xx**: The service returned an HTTP error (check server logs)
- **grpc-status non-zero**: The gRPC call failed at the application level

**Note:** The probe uses the same URLs configured for `--rpc-url` and `--remote-prover-urls`. For the probe to work from a browser, these services must:
1. Have gRPC-Web support enabled (e.g., via Envoy, grpc-web proxy, or native tonic-web)
2. Allow CORS requests from the monitor's origin (or use `Access-Control-Allow-Origin: *`)

## Account Management

When the network transaction service is enabled, the monitor manages the necessary Miden accounts:

### Created Accounts

**Network Account:**
- Implements a simple counter with increment functionality
- Includes authentication logic that restricts access to the network account
- Uses custom MASM script with account ID-based authorization
- Automatically created if not present

**Wallet Account:**
- Uses RpoFalcon512 authentication scheme
- Contains authentication keys for transaction signing
- Automatically created if not present

### Account File Management

The monitor automatically:
1. Checks for existing account files on startup
2. Creates new accounts if files don't exist
3. Deploys accounts to the network via RPC
4. Saves the wallet and counter contract account in the specified file paths (default: `wallet_account.mac` and `counter_program.mac`)

### Example Usage

```bash
# Start monitor with counter task and default account files
miden-network-monitor start --rpc-url https://testnet.miden.io:443

# Start monitor with custom account file paths
miden-network-monitor start \
  --disable-ntx-service=false \
  --rpc-url https://testnet.miden.io:443 \
  --wallet-filepath my_wallet.mac \
  --counter-filepath my_counter.mac

# The generated files can be loaded in Miden applications:
# - wallet_account.mac: Contains the wallet account with authentication keys
# - counter_program.mac: Contains the counter program account
```

## Future Monitor Items

- Match explorer's block height with node's chain tip.
- Add more transaction types to the test suite (P2ID, Swap, etc.).

## License
This project is [MIT licensed](../../LICENSE).
