miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(err(Debug))]
fn debug_error() -> Result<(), std::io::Error> {
    Ok(())
}

#[instrument(err(Display, level = "warn"))]
fn display_error() -> Result<(), std::io::Error> {
    Ok(())
}

fn main() {}
