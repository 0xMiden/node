// Browser-only bits the server cannot do for us:
//   1. gRPC-Web probes — issued from the user's browser to test reachability + CORS from
//      the same origin the dashboard runs in.
//   2. copy-to-clipboard via navigator.clipboard.
//
// The server emits placeholder `<div class="probe-section">` slots and `data-grpc-url` /
// `data-grpc-path` attributes on every card that needs probing. We populate those slots after
// each htmx swap (and on initial load).

"use strict";

const PROBE_INTERVAL_MS = 30000;
const ABBREV_ERROR_LEN = 40;

/** Cache of last probe per URL so re-renders show instantly without a full re-probe. */
const probeResults = new Map();

let periodicProbeTimer = null;

const rootStyle = getComputedStyle(document.documentElement);
const COLOR_HEALTHY = rootStyle.getPropertyValue("--color-healthy").trim();
const COLOR_UNHEALTHY = rootStyle.getPropertyValue("--color-unhealthy").trim();

// gRPC-Web probe
// ============================================================================

async function probeGrpcWeb(baseUrl, grpcPath) {
    const startTime = performance.now();
    const normalizedUrl = baseUrl.replace(/\/+$/, "");
    const fullUrl = `${normalizedUrl}${grpcPath}`;

    // Empty google.protobuf.Empty body framed for gRPC-Web:
    // 1 byte compressed flag (0x00) + 4 bytes big-endian length (0x00000000).
    const emptyGrpcWebFrame = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00]);

    const headers = {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
    };
    // The Miden RPC service requires its custom Accept header; the remote prover is fine with
    // the standard gRPC-Web content type.
    headers["Accept"] = grpcPath.startsWith("/rpc.")
        ? "application/vnd.miden"
        : "application/grpc-web+proto";

    try {
        const response = await fetch(fullUrl, {
            method: "POST",
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

        const responseBytes = new Uint8Array(await response.arrayBuffer());
        const grpcStatus = parseGrpcWebTrailers(responseBytes);
        if (grpcStatus === "0" || grpcStatus === null) {
            return { ok: true, latencyMs, error: null };
        }
        return { ok: false, latencyMs, error: `grpc-status: ${grpcStatus}` };
    } catch (err) {
        const latencyMs = Math.round(performance.now() - startTime);
        if (err instanceof TypeError) {
            return { ok: false, latencyMs, error: "CORS / Network error: " + err.message };
        }
        return { ok: false, latencyMs, error: err.message || String(err) };
    }
}

function parseGrpcWebTrailers(data) {
    let offset = 0;
    while (offset + 5 <= data.length) {
        const flag = data[offset];
        const length =
            (data[offset + 1] << 24) |
            (data[offset + 2] << 16) |
            (data[offset + 3] << 8) |
            data[offset + 4];
        offset += 5;
        if (offset + length > data.length) break;

        if (flag === 0x80) {
            const trailerText = new TextDecoder().decode(data.slice(offset, offset + length));
            for (const line of trailerText.split(/\r?\n/)) {
                const m = line.match(/^grpc-status:\s*(\d+)/i);
                if (m) return m[1];
            }
        }
        offset += length;
    }
    return null;
}

// Render + dispatch
// ============================================================================

function probeTargets() {
    return Array.from(document.querySelectorAll("[data-grpc-url][data-grpc-path]")).map((el) => ({
        el,
        url: el.dataset.grpcUrl,
        path: el.dataset.grpcPath,
    }));
}

async function runProbes() {
    const targets = probeTargets();
    if (targets.length === 0) return;
    await Promise.all(
        targets.map(async ({ el, url, path }) => {
            const result = await probeGrpcWeb(url, path);
            probeResults.set(url, { ...result, timestamp: Date.now() });
            paintProbe(el, url);
        }),
    );
}

function paintProbe(detailsEl, url) {
    const slot = detailsEl.querySelector(".probe-section");
    if (!slot) return;
    const result = probeResults.get(url);
    if (!result) return;

    const cls = result.ok ? "probe-ok" : "probe-failed";
    const text = result.ok ? "OK" : "FAILED";
    const seconds = Math.floor((Date.now() - result.timestamp) / 1000);
    const timeAgo =
        seconds < 60 ? `${seconds}s ago` :
        seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` :
        `${Math.floor(seconds / 3600)}h ago`;
    const errorAbbrev =
        result.error && result.error.length > ABBREV_ERROR_LEN
            ? result.error.substring(0, ABBREV_ERROR_LEN) + "..."
            : result.error;

    slot.innerHTML = `
        <div class="probe-result ${cls}">
            <span class="probe-status-badge">gRPC-Web: ${text}</span>
            <span class="probe-latency">${result.latencyMs}ms</span>
            ${result.error ? `<span class="probe-error" title="${escapeAttr(result.error)}">${escapeText(errorAbbrev)}</span>` : ""}
            <span class="probe-time">${timeAgo}</span>
        </div>
    `;
}

/** After an htmx swap we still have cached probe results — paint them immediately. */
function repaintAllFromCache() {
    for (const { el, url } of probeTargets()) {
        if (probeResults.has(url)) paintProbe(el, url);
    }
}

function escapeAttr(s) {
    return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
function escapeText(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Clipboard
// ============================================================================

async function copyToClipboard(text, event) {
    const button = event.target.closest(".copy-button");
    if (!button) return;
    try {
        await navigator.clipboard.writeText(text);
        const original = button.innerHTML;
        button.innerHTML = '<svg class="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>';
        button.style.color = COLOR_HEALTHY;
        setTimeout(() => {
            button.innerHTML = original;
            button.style.color = "";
        }, 2000);
    } catch (err) {
        console.error("Failed to copy to clipboard:", err);
        button.style.color = COLOR_UNHEALTHY;
        setTimeout(() => {
            button.style.color = "";
        }, 2000);
    }
}
window.copyToClipboard = copyToClipboard;

// Lifecycle
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
    runProbes();
    periodicProbeTimer = setInterval(runProbes, PROBE_INTERVAL_MS);
});

document.body.addEventListener("htmx:afterSwap", (e) => {
    if (e.detail && e.detail.target && e.detail.target.id === "status-container") {
        repaintAllFromCache();
        // Re-run a probe for any newly added target that we haven't seen before.
        const known = new Set(probeResults.keys());
        const fresh = probeTargets().some((t) => !known.has(t.url));
        if (fresh) runProbes();
    }
});

window.addEventListener("beforeunload", () => {
    if (periodicProbeTimer) clearInterval(periodicProbeTimer);
});
