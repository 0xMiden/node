miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::instrument;

#[instrument(ret)]
fn plain_return() -> u32 {
    7
}

#[instrument(ret(Debug, level = "info"))]
fn formatted_return() -> u32 {
    7
}

#[instrument(err, ret)]
fn result_return() -> Result<(), std::io::Error> {
    Ok(())
}

fn main() {}
