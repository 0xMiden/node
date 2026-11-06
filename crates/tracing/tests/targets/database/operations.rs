#[miden_node_tracing::instrument_v2]
pub fn parent() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

#[miden_node_tracing::instrument_v2(target = "miden::rpc::server")]
pub fn explicit_override() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

#[miden_node_tracing::instrument_v2(
    name = "database.load",
    level = "debug",
    fields(service.name = "store"),
    err(level = "warn"),
)]
pub fn configured() -> std::io::Result<()> {
    miden_node_tracing::miden_span_record!(block.number = 42_u32);
    Err(std::io::Error::other("database unavailable"))
}

#[miden_node_tracing::instrument_v2(err, target = "miden::rpc::server")]
pub fn explicit_error() -> std::io::Result<()> {
    Err(std::io::Error::other("rpc unavailable"))
}
