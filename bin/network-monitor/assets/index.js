// Miden Network Monitor - Frontend JavaScript
// ================================================================================================

let statusData = null;
let updateInterval = null;
const EXPLORER_LAG_TOLERANCE = 20; // max allowed block delta vs RPC, roughly 1 minute

// Store gRPC-Web probe results keyed by service URL
const grpcWebProbeResults = new Map();

// gRPC-Web probe implementation
// ================================================================================================

/**
 * Performs a gRPC-Web probe to the given URL and path.
 * This sends a real browser-originated gRPC-Web request to test connectivity,
 * CORS configuration, and gRPC-Web protocol handling.
 *
 * @param {string} baseUrl - The base URL of the service (e.g., "https://prover.example.com:443")
 * @param {string} grpcPath - The gRPC method path (e.g., "/remote_prover.ProxyStatusApi/Status")
 * @returns {Promise<{ok: boolean, latencyMs: number, error: string|null}>}
 */
async function probeGrpcWeb(baseUrl, grpcPath) {
    const startTime = performance.now();

    // Normalize URL: remove trailing slash from baseUrl
    const normalizedUrl = baseUrl.replace(/\/+$/, '');
    const fullUrl = `${normalizedUrl}${grpcPath}`;

    // gRPC-Web frame for google.protobuf.Empty:
    // - 1 byte compressed flag = 0x00 (not compressed)
    // - 4 bytes big-endian length = 0x00000000 (empty message)
    const emptyGrpcWebFrame = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00]);

    // Build headers - RPC service requires custom Accept header
    const headers = {
        'Content-Type': 'application/grpc-web+proto',
        'X-Grpc-Web': '1',
    };

    // The RPC service requires 'application/vnd.miden' in Accept header
    // (this is the custom media type used by the Miden gRPC clients)
    // The remote prover accepts standard gRPC-Web content types
    if (grpcPath.startsWith('/rpc.')) {
        headers['Accept'] = 'application/vnd.miden';
    } else {
        headers['Accept'] = 'application/grpc-web+proto';
    }

    try {
        const response = await fetch(fullUrl, {
            method: 'POST',
            headers,
            body: emptyGrpcWebFrame,
        });

        const latencyMs = Math.round(performance.now() - startTime);

        if (!response.ok) {
            return {
                ok: false,
                latencyMs,
                error: `HTTP ${response.status}: ${response.statusText}`,
            };
        }

        // Read the response body as bytes
        const responseBytes = new Uint8Array(await response.arrayBuffer());

        // Parse gRPC-Web response to extract grpc-status from trailers
        const grpcStatus = parseGrpcWebTrailers(responseBytes);

        if (grpcStatus === '0' || grpcStatus === null) {
            // grpc-status 0 means OK; null means no trailer found (might still be OK)
            return { ok: true, latencyMs, error: null };
        } else {
            return {
                ok: false,
                latencyMs,
                error: `grpc-status: ${grpcStatus}`,
            };
        }
    } catch (err) {
        const latencyMs = Math.round(performance.now() - startTime);

        // TypeError: Failed to fetch usually indicates CORS or network error
        if (err instanceof TypeError) {
            return {
                ok: false,
                latencyMs,
                error: 'CORS / Network error: ' + err.message,
            };
        }

        return {
            ok: false,
            latencyMs,
            error: err.message || String(err),
        };
    }
}

/**
 * Parses gRPC-Web response bytes to extract the grpc-status from trailers.
 * gRPC-Web trailers are sent as a frame with flag 0x80.
 *
 * @param {Uint8Array} data - The response body bytes
 * @returns {string|null} - The grpc-status value, or null if not found
 */
function parseGrpcWebTrailers(data) {
    let offset = 0;

    while (offset + 5 <= data.length) {
        const flag = data[offset];
        const length = (data[offset + 1] << 24) |
                       (data[offset + 2] << 16) |
                       (data[offset + 3] << 8) |
                       data[offset + 4];

        offset += 5;

        if (offset + length > data.length) break;

        // Flag 0x80 indicates trailers
        if (flag === 0x80) {
            const trailerBytes = data.slice(offset, offset + length);
            const trailerText = new TextDecoder().decode(trailerBytes);

            // Parse trailer headers (format: "key: value\r\n")
            const lines = trailerText.split(/\r?\n/);
            for (const line of lines) {
                const match = line.match(/^grpc-status:\s*(\d+)/i);
                if (match) {
                    return match[1];
                }
            }
        }

        offset += length;
    }

    return null;
}

// Interval for periodic gRPC-Web probing
let grpcWebProbeInterval = null;
const GRPC_WEB_PROBE_INTERVAL_MS = 30000; // Probe every 30 seconds

/**
 * Collects all gRPC-Web endpoints that need to be probed from the current status data.
 *
 * @returns {Array<{serviceKey: string, baseUrl: string, grpcPath: string}>}
 */
function collectGrpcWebEndpoints() {
    if (!statusData || !statusData.services) return [];

    const endpoints = [];

    for (const service of statusData.services) {
        if (service.details) {
            // RPC service
            if (service.details.RpcStatus && service.details.RpcStatus.url) {
                endpoints.push({
                    serviceKey: service.details.RpcStatus.url,
                    baseUrl: service.details.RpcStatus.url,
                    grpcPath: '/rpc.Api/Status',
                });
            }
            // Remote Prover service
            if (service.details.RemoteProverStatus && service.details.RemoteProverStatus.url) {
                endpoints.push({
                    serviceKey: service.details.RemoteProverStatus.url,
                    baseUrl: service.details.RemoteProverStatus.url,
                    grpcPath: '/remote_prover.ProxyStatusApi/Status',
                });
            }
        }
    }

    return endpoints;
}

/**
 * Runs gRPC-Web probes for all collected endpoints.
 * Results are stored in grpcWebProbeResults and display is updated.
 */
async function runGrpcWebProbes() {
    const endpoints = collectGrpcWebEndpoints();
    if (endpoints.length === 0) return;

    // Run all probes in parallel
    const probePromises = endpoints.map(async ({ serviceKey, baseUrl, grpcPath }) => {
        const result = await probeGrpcWeb(baseUrl, grpcPath);
        grpcWebProbeResults.set(serviceKey, {
            ...result,
            timestamp: Date.now(),
        });
    });

    await Promise.all(probePromises);

    // Re-render to show updated results
    updateDisplay();
}

/**
 * Renders the probe result badge for a service.
 *
 * @param {string} serviceKey - Unique key for the service
 * @returns {string} - HTML string for the probe result
 */
function renderProbeResult(serviceKey) {
    const result = grpcWebProbeResults.get(serviceKey);
    if (!result) return '';

    const statusClass = result.ok ? 'probe-ok' : 'probe-failed';
    const statusText = result.ok ? 'OK' : 'FAILED';
    const seconds = Math.floor((Date.now() - result.timestamp) / 1000);
    const timeAgo = seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : `${Math.floor(seconds / 3600)}h ago`;
    const errorDisplay = result.error && result.error.length > 40 ? result.error.substring(0, 40) + '...' : result.error;

    return `
        <div class="probe-result ${statusClass}">
            <span class="probe-status-badge">gRPC-Web: ${statusText}</span>
            <span class="probe-latency">${result.latencyMs}ms</span>
            ${result.error ? `<span class="probe-error" title="${result.error}">${errorDisplay}</span>` : ''}
            <span class="probe-time">${timeAgo}</span>
        </div>
    `;
}

/**
 * Renders the gRPC-Web probe result section for a service.
 * Shows "Checking..." if no result yet, otherwise shows the probe result.
 *
 * @param {string} serviceKey - Unique key for the service (the URL)
 * @returns {string} - HTML string for the probe result section
 */
function renderGrpcWebProbeSection(serviceKey) {
    const result = grpcWebProbeResults.get(serviceKey);

    if (!result) {
        return `
            <div class="probe-section">
                <div class="probe-result probe-pending">
                    <span class="probe-spinner"></span>
                    <span class="probe-status-badge">gRPC-Web: Checking...</span>
                </div>
            </div>
        `;
    }

    return `
        <div class="probe-section">
            ${renderProbeResult(serviceKey)}
        </div>
    `;
}


const COPY_ICON = `
    <svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
    </svg>
`;

function renderCopyButton(value, label) {
    if (!value) return '';
    const escapedValue = JSON.stringify(value);
    return `
        <button class="copy-button" onclick='copyToClipboard(${escapedValue}, event)' title="Copy full ${label}">
            ${COPY_ICON}
        </button>
    `;
}

function formatSuccessRate(successCount, failureCount) {
    const total = successCount + failureCount;
    if (!total) {
        return 'N/A';
    }

    return `${((successCount / total) * 100).toFixed(1)}%`;
}

async function fetchStatus() {
    try {
        const response = await fetch('/status');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        statusData = await response.json();
        updateDisplay();
    } catch (error) {
        console.error('Error fetching status:', error);
        showError('Failed to fetch network status: ' + error.message);
    }
}

// Merge Remote Prover status and test entries into a single card per prover.
function mergeProverStatusAndTests(services) {
    const testsByName = new Map();
    const merged = [];
    const usedTests = new Set();

    services.forEach(service => {
        if (service.details && service.details.RemoteProverTest) {
            testsByName.set(service.name, service);
        }
    });

    services.forEach(service => {
        if (service.details && service.details.RemoteProverStatus) {
            const test = testsByName.get(service.name);
            if (test) {
                usedTests.add(service.name);
            }
            merged.push({
                ...service,
                testDetails: test?.details?.RemoteProverTest ?? null,
                testStatus: test?.status ?? null,
                testError: test?.error ?? null
            });
        } else if (!(service.details && service.details.RemoteProverTest)) {
            // Non-prover entries pass through unchanged
            merged.push(service);
        }
    });

    // Add orphaned tests (in case a test arrives before a status)
    testsByName.forEach((test, name) => {
        if (!usedTests.has(name)) {
            merged.push({
                name,
                status: test.status,
                last_checked: test.last_checked,
                error: test.error,
                details: null,
                testDetails: test.details.RemoteProverTest,
                testStatus: test.status,
                testError: test.error
            });
        }
    });

    return merged;
}

function updateDisplay() {
    if (!statusData) return;

    const container = document.getElementById('status-container');
    const lastUpdated = document.getElementById('last-updated');
    const overallStatus = document.getElementById('overall-status');
    const servicesCount = document.getElementById('services-count');

    // Update last updated time
    const lastUpdateTime = new Date(statusData.last_updated * 1000);
    lastUpdated.textContent = lastUpdateTime.toLocaleString();

    // Group remote prover status + test into single cards
    const processedServices = mergeProverStatusAndTests(statusData.services);
    const rpcService = processedServices.find(s => s.details && s.details.RpcStatus);
    const rpcChainTip =
        rpcService?.details?.RpcStatus?.store_status?.chain_tip ??
        rpcService?.details?.RpcStatus?.block_producer_status?.chain_tip ??
        null;

    // Count healthy vs unhealthy services
    const healthyServices = processedServices.filter(s => s.status === 'Healthy').length;
    const totalServices = processedServices.length;
    const allHealthy = healthyServices === totalServices;

    // Update footer
    overallStatus.textContent = allHealthy ? 'All Systems Operational' : `${healthyServices}/${totalServices} Services Healthy`;
    overallStatus.style.color = allHealthy ? '#22C55D' : '#ff5500';
    servicesCount.textContent = `${totalServices} Services`;

    // Generate status cards
    const serviceCardsHtml = processedServices.map(service => {
        const isHealthy = service.status === 'Healthy';
        const statusColor = isHealthy ? '#22C55D' : '#ff5500';
        const statusIcon = isHealthy ? '✓' : '✗';
        const numOrDash = value => isHealthy ? (value?.toLocaleString?.() ?? value ?? '-') : '-';
        const timeOrDash = ts => {
            if (!isHealthy) return '-';
            return ts ? new Date(ts * 1000).toLocaleString() : '-';
        };
        const commitmentOrDash = (value, label) => isHealthy && value
            ? `
                ${value.substring(0, 20)}...
                ${renderCopyButton(value, label)}
            `
            : '-';

        const explorerStats = service.details?.ExplorerStatus;
        const isExplorerService = service.name?.toLowerCase().includes('explorer');
        const deltaBlock = (isHealthy && explorerStats && rpcChainTip !== null)
            ? explorerStats.block_number - rpcChainTip
            : null;
        const deltaWarning =
            deltaBlock !== null && Math.abs(deltaBlock) > EXPLORER_LAG_TOLERANCE
                ? `Explorer tip is ${Math.abs(deltaBlock)} blocks ${deltaBlock > 0 ? 'ahead' : 'behind'}`
                : null;
        let explorerWarningHtml = '';

        let detailsHtml = '';
        if (service.details) {
            const details = service.details;
            detailsHtml = `
                <div class="service-details">
                    ${details.RpcStatus ? `
                        <div class="detail-item"><strong>Version:</strong> ${details.RpcStatus.version}</div>
                        ${details.RpcStatus.genesis_commitment ? `
                            <div class="detail-item">
                                <strong>Genesis:</strong>
                                <span class="genesis-value">0x${details.RpcStatus.genesis_commitment.substring(0, 20)}...</span>
                                ${renderCopyButton(details.RpcStatus.genesis_commitment, 'genesis commitment')}
                            </div>
                        ` : ''}
                        ${details.RpcStatus.url ? renderGrpcWebProbeSection(details.RpcStatus.url) : ''}
                        ${details.RpcStatus.store_status ? `
                            <div class="nested-status">
                                <div class="detail-item"><strong>Store</strong></div>
                                <div class="metric-row">
                                    <span class="metric-label">Version:</span>
                                    <span class="metric-value">${details.RpcStatus.store_status.version}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Status:</span>
                                    <span class="metric-value">${details.RpcStatus.store_status.status}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Chain Tip:</span>
                                    <span class="metric-value">${details.RpcStatus.store_status.chain_tip}</span>
                                </div>
                            </div>
                        ` : ''}
                        ${details.RpcStatus.block_producer_status ? `
                            <div class="nested-status">
                                <div class="detail-item"><strong>Block Producer</strong></div>
                                <div class="metric-row">
                                    <span class="metric-label">Version:</span>
                                    <span class="metric-value">${details.RpcStatus.block_producer_status.version}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Status:</span>
                                    <span class="metric-value">${details.RpcStatus.block_producer_status.status}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Chain Tip:</span>
                                    <span class="metric-value">${details.RpcStatus.block_producer_status.chain_tip}</span>
                                </div>
                                <div class="nested-status mempool-stats">
                                    <strong>Mempool stats:</strong>
                                    <div class="metric-row">
                                        <span class="metric-label">Unbatched TXs:</span>
                                        <span class="metric-value">${details.RpcStatus.block_producer_status.mempool.unbatched_transactions}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Proposed Batches:</span>
                                        <span class="metric-value">${details.RpcStatus.block_producer_status.mempool.proposed_batches}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Proven Batches:</span>
                                        <span class="metric-value">${details.RpcStatus.block_producer_status.mempool.proven_batches}</span>
                                    </div>
                                </div>
                            </div>
                        ` : ''}
                    ` : ''}
                    ${details.RemoteProverStatus ? `
                        <div class="nested-status">
                            <strong>Prover Status (${details.RemoteProverStatus.url}):</strong>
                            <div class="detail-item"><strong>Version:</strong> ${details.RemoteProverStatus.version}</div>
                            <div class="nested-status">
                                <strong>Supported Proof Type:</strong> ${details.RemoteProverStatus.supported_proof_type}
                            </div>
                            ${details.RemoteProverStatus.workers && details.RemoteProverStatus.workers.length > 0 ? `
                                <div class="nested-status">
                                    <strong>Workers (${details.RemoteProverStatus.workers.length}):</strong>
                                    ${details.RemoteProverStatus.workers.map(worker => `
                                        <div class="worker-status">
                                            <span class="worker-name">${worker.name}</span> -
                                            <span class="worker-version">${worker.version}</span> -
                                            <span class="worker-status-badge ${worker.status === 'Healthy' ? 'healthy' : worker.status === 'Unhealthy' ? 'unhealthy' : 'unknown'}">${worker.status}</span>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                            ${renderGrpcWebProbeSection(details.RemoteProverStatus.url)}
                        </div>
                    ` : ''}
                    ${details.FaucetTest ? `
                        <div class="nested-status">
                            <strong>Faucet:</strong>
                            <div class="test-metrics ${service.status === 'Healthy' ? 'healthy' : 'unhealthy'}">
                                <div class="metric-row">
                                    <span class="metric-label">Success Rate:</span>
                                    <span class="metric-value">${formatSuccessRate(details.FaucetTest.success_count, details.FaucetTest.failure_count)}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Last Response Time:</span>
                                    <span class="metric-value">${details.FaucetTest.test_duration_ms}ms</span>
                                </div>
                                ${details.FaucetTest.last_tx_id ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Last TX ID:</span>
                                        <span class="metric-value">${details.FaucetTest.last_tx_id.substring(0, 16)}...${renderCopyButton(details.FaucetTest.last_tx_id, 'TX ID')}</span>
                                    </div>
                                ` : ''}
                                ${details.FaucetTest.challenge_difficulty ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Last Challenge Difficulty:</span>
                                        <span class="metric-value">~${details.FaucetTest.challenge_difficulty} bits</span>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                        ${details.FaucetTest.faucet_metadata ? `
                            <div class="nested-status">
                                <strong>Faucet Token Info:</strong>
                                <div class="test-metrics ${service.status === "Healthy" ? "healthy" : "unhealthy"}">
                                    <div class="metric-row">
                                        <span class="metric-label">Token ID:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.id.substring(0, 16)}...${renderCopyButton(details.FaucetTest.faucet_metadata.id, 'token ID')}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Version:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.version || '-'}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Current Issuance:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.issuance.toLocaleString()}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Max Supply:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.max_supply.toLocaleString()}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Decimals:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.decimals}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Base Amount:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.base_amount.toLocaleString()}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">PoW Difficulty:</span>
                                        <span class="metric-value">${details.FaucetTest.faucet_metadata.pow_load_difficulty}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Explorer URL:</span>
                                        <span class="metric-value">
                                            <a href="${details.FaucetTest.faucet_metadata.explorer_url}" target="_blank" rel="noopener noreferrer">
                                                ${details.FaucetTest.faucet_metadata.explorer_url}
                                            </a>
                                        </span>
                                    </div>
                                </div>
                            </div>
                          ` : ''}
                    ` : ''}
                    ${details.NtxIncrement ? `
                        <div class="nested-status">
                            <strong>Local Transactions:</strong>
                            <div class="test-metrics ${service.status === 'Healthy' ? 'healthy' : 'unhealthy'}">
                                <div class="metric-row">
                                    <span class="metric-label">Success Rate:</span>
                                    <span class="metric-value">${formatSuccessRate(details.NtxIncrement.success_count, details.NtxIncrement.failure_count)}</span>
                                </div>
                                ${details.NtxIncrement.last_latency_blocks !== null && details.NtxIncrement.last_latency_blocks !== undefined ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Latency:</span>
                                        <span class="metric-value">${details.NtxIncrement.last_latency_blocks} blocks</span>
                                    </div>
                                ` : ''}
                                ${details.NtxIncrement.last_tx_id ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Last TX ID:</span>
                                        <span class="metric-value">${details.NtxIncrement.last_tx_id.substring(0, 16)}...${renderCopyButton(details.NtxIncrement.last_tx_id, 'TX ID')}</span>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    ` : ''}
                    ${details.NtxTracking ? `
                        <div class="nested-status">
                            <strong>Network Transactions:</strong>
                            <div class="test-metrics ${service.status === 'Healthy' ? 'healthy' : 'unhealthy'}">
                                <div class="metric-row">
                                    <span class="metric-label">Current Value:</span>
                                    <span class="metric-value">${details.NtxTracking.current_value ?? '-'}</span>
                                </div>
                                ${details.NtxTracking.expected_value ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Expected Value:</span>
                                        <span class="metric-value">${details.NtxTracking.expected_value}</span>
                                    </div>
                                ` : ''}
                                ${details.NtxTracking.pending_increments !== null && details.NtxTracking.pending_increments !== undefined ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Pending Notes:</span>
                                        <span class="metric-value">${details.NtxTracking.pending_increments}</span>
                                    </div>
                                ` : ''}
                                ${details.NtxTracking.last_updated ? `
                                    <div class="metric-row">
                                        <span class="metric-label">Last Updated:</span>
                                        <span class="metric-value">${new Date(details.NtxTracking.last_updated * 1000).toLocaleString()}</span>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    ` : ''}
                    ${service.testDetails ? `
                        <div class="nested-status">
                            <strong>Proof Generation Testing (${service.testDetails.proof_type}):</strong>
                            <div class="test-metrics ${service.testStatus === 'Healthy' ? 'healthy' : 'unhealthy'}">
                                <div class="metric-row">
                                    <span class="metric-label">Success Rate:</span>
                                    <span class="metric-value">${formatSuccessRate(service.testDetails.success_count, service.testDetails.failure_count)}</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Last Response Time:</span>
                                    <span class="metric-value">${service.testDetails.test_duration_ms}ms</span>
                                </div>
                                <div class="metric-row">
                                    <span class="metric-label">Last Proof Size:</span>
                                    <span class="metric-value">${(service.testDetails.proof_size_bytes / 1024).toFixed(2)} KB</span>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Always render explorer block for explorer services, even if stats are missing.
        if (isExplorerService) {
            detailsHtml += `
                <div class="service-details">
                    <div class="nested-status">
                        <strong>Explorer:</strong>
                        <div class="metric-row">
                            <span class="metric-label">Block Height:</span>
                            <span class="metric-value">${explorerStats ? numOrDash(explorerStats.block_number) : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">RPC Chain Tip:</span>
                            <span class="metric-value">${isHealthy && rpcChainTip !== null ? rpcChainTip : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Block Time:</span>
                            <span class="metric-value">${explorerStats ? timeOrDash(explorerStats.timestamp) : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Block Commitment:</span>
                            <span class="metric-value">${explorerStats ? commitmentOrDash(explorerStats.block_commitment, 'block commitment') : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Chain Commitment:</span>
                            <span class="metric-value">${explorerStats ? commitmentOrDash(explorerStats.chain_commitment, 'chain commitment') : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Proof Commitment:</span>
                            <span class="metric-value">${explorerStats ? commitmentOrDash(explorerStats.proof_commitment, 'proof commitment') : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Transactions:</span>
                            <span class="metric-value">${explorerStats ? numOrDash(explorerStats.number_of_transactions) : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Nullifiers:</span>
                            <span class="metric-value">${explorerStats ? numOrDash(explorerStats.number_of_nullifiers) : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Notes:</span>
                            <span class="metric-value">${explorerStats ? numOrDash(explorerStats.number_of_notes) : '-'}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Account Updates:</span>
                            <span class="metric-value">${explorerStats ? numOrDash(explorerStats.number_of_account_updates) : '-'}</span>
                        </div>
                    </div>
                </div>
            `;

            if (deltaWarning) {
                explorerWarningHtml = `
                    <div class="warning-banner">
                        <div class="metric-row">
                            <span class="metric-label">Explorer vs RPC</span>
                        </div>
                        <div class="warning-text">${deltaWarning}</div>
                    </div>
                `;
            }
        }

        return `
            <div class="service-card ${isHealthy ? 'healthy' : 'unhealthy'}">
                <div class="service-header">
                    <div class="service-name">${service.name}</div>
                    <div class="service-status" style="color: ${statusColor}">
                        ${statusIcon} ${service.status.toUpperCase()}
                    </div>
                </div>
                <div class="service-content">
                    ${detailsHtml}
                    ${explorerWarningHtml}
                </div>
                <div class="service-timestamp">
                    Last checked: ${new Date(service.last_checked * 1000).toLocaleString()}
                </div>
            </div>
        `;
    }).join('');

    container.innerHTML = serviceCardsHtml;

    // Add refresh button that spans the full grid
    container.innerHTML += `
        <div class="refresh-button-container">
            <button class="button" onclick="fetchStatus()">
                <svg class="button-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M23 4v6h-6M1 20v-6h6M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/>
                </svg>
                Refresh Status
            </button>
        </div>
    `;
}

function showError(message) {
    const container = document.getElementById('status-container');
    container.innerHTML = `
        <div class="error-message" style="display: block;">
            ${message}
        </div>
        <div class="refresh-button-container">
            <button class="button" onclick="fetchStatus()">
                <svg class="button-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M23 4v6h-6M1 20v-6h6M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"/>
                </svg>
                Retry
            </button>
        </div>
    `;
}

async function copyToClipboard(text, event) {
    const button = event.target.closest('.copy-button');
    if (!button) return;

    try {
        await navigator.clipboard.writeText(text);
        // Show a brief success indicator
        const originalContent = button.innerHTML;
        button.innerHTML = '<svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
        button.style.color = '#22C55D';

        setTimeout(() => {
            button.innerHTML = originalContent;
            button.style.color = '';
        }, 2000);
    } catch (err) {
        console.error('Failed to copy to clipboard:', err);
        // Show error feedback on button
        button.style.color = '#ff5500';
        setTimeout(() => {
            button.style.color = '';
        }, 2000);
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Initial load and set up auto-refresh
    fetchStatus().then(() => {
        // Start gRPC-Web probing after initial status fetch
        runGrpcWebProbes();
        grpcWebProbeInterval = setInterval(runGrpcWebProbes, GRPC_WEB_PROBE_INTERVAL_MS);
    });
    updateInterval = setInterval(fetchStatus, 10000); // Refresh every 10 seconds
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    if (grpcWebProbeInterval) {
        clearInterval(grpcWebProbeInterval);
    }
});

