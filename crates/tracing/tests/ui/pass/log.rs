use miden_node_tracing::{debug, error, info, trace, warn};

fn main() {
    // ── plain message ─────────────────────────────────────────────────────────

    error!("hard failure");
    warn!("something looks off");
    info!("block applied");
    debug!("trace point");
    trace!("tick");

    // ── format string ─────────────────────────────────────────────────────────

    error!("failed after {} retries", 3);
    warn!("retrying after {}ms", 100u64);
    info!("migrated {} rows", 42usize);
    debug!("response size: {} bytes", 128usize);
    trace!("loop iteration {}", 7u32);

    // ── component + message ───────────────────────────────────────────────────

    error!(rpc: "connection refused");
    warn!(store: "slow query detected");
    info!(rpc: "server started");
    debug!(store: "cache miss");
    trace!(rpc: "entering handler");

    // ── component + format string ─────────────────────────────────────────────

    error!(rpc: "rejected {} requests", 5u32);
    warn!(store: "table has {} rows", 1000usize);
    info!(rpc: "listening on port {}", 8080u16);
    debug!(store: "query took {}ms", 12u64);
    trace!(rpc: "payload {} bytes", 256usize);

    // ── string-literal component ──────────────────────────────────────────────

    warn!("block-producer": "batch timeout");
    info!("block-producer": "produced block {}", 42u32);

    // ── allowlisted dotted field, Display ─────────────────────────────────────

    warn!(account.id = %1u64, "unexpected account");
    error!(nullifier.id = %2u64, "double spend");
    info!(block.number = 3u32, "block committed");

    // ── allowlisted dotted field, Debug ───────────────────────────────────────

    warn!(account.id = 1u64, "unexpected account");
    debug!(block.number = 3u32, "processing");

    // ── allowlisted dotted field, explicit Debug ──────────────────────────────

    trace!(nullifier.id = ?2u64, "lookup");

    // ── multiple allowlisted fields + message ─────────────────────────────────

    warn!(account.id = %1u64, block.number = 3u32, "state inconsistency");
    error!(nullifier.id = %2u64, block.number = 3u32, "double spend at block");

    // ── fields only, no message ───────────────────────────────────────────────

    warn!(account.id = %1u64, block.number = 3u32);
    info!(nullifier.id = %2u64);
}
