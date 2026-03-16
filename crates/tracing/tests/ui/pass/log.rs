use miden_node_tracing::{debug, error, info, trace, warn};

fn main() {
    // plain message at each level
    error!("hard failure");
    warn!("something looks off");
    info!("block applied");
    debug!("trace point");
    trace!("tick");

    // format string at each level
    error!("failed after {} retries", 3);
    warn!("retrying after {}ms", 100);
    info!("migrated {} rows", 42usize);
    debug!("response size: {}", 128usize);
    trace!("entering handler: {}", "foo");
}
