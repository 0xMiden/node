use miden_node_tracing::miden_instrument;

#[miden_instrument(err(Debug))]
fn debug_error() -> Result<(), std::io::Error> {
    Ok(())
}

#[miden_instrument(err(Display, level = "warn"))]
fn display_error() -> Result<(), std::io::Error> {
    Ok(())
}

fn main() {}
