#[miden_node_tracing::instrument_v2]
pub fn target() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

pub fn event() {
    miden_node_tracing::info_v2!("maintenance.event");
}

pub fn debug_enabled() -> bool {
    miden_node_tracing::enabled_v2!(tracing::Level::DEBUG)
}
