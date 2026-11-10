#[miden_node_tracing::instrument]
pub fn target() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

pub fn event() {
    miden_node_tracing::info!("maintenance.event");
}

pub fn debug_enabled() -> bool {
    miden_node_tracing::enabled!(tracing::Level::DEBUG)
}
