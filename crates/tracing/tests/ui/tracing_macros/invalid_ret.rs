use miden_node_tracing::miden_instrument;

#[miden_instrument(ret)]
fn plain_return() -> u32 {
    7
}

#[miden_instrument(ret(Debug, level = "info"))]
fn formatted_return() -> u32 {
    7
}

#[miden_instrument(err, ret)]
fn result_return() -> Result<(), std::io::Error> {
    Ok(())
}

fn main() {}
