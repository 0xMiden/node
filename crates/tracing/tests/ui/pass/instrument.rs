use miden_node_tracing::instrument;

#[derive(Debug)]
struct MyError;
impl std::fmt::Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("my error")
    }
}
impl std::error::Error for MyError {}

// bare – no args
#[instrument]
fn bare() {}

// component only
#[instrument(rpc:)]
fn component_only() {}

// ret on a plain fn
#[instrument(rpc: ret)]
fn with_ret() -> u32 { 42 }

// err on a Result fn
#[instrument(store: err)]
fn with_err() -> Result<(), MyError> { Ok(()) }

// report on a Result fn
#[instrument(rpc: report)]
fn with_report() -> Result<(), MyError> { Ok(()) }

// ret + err on a Result fn
#[instrument(rpc: ret, err)]
fn with_ret_err() -> Result<u32, MyError> { Ok(42) }

// ret + report on a Result fn
#[instrument(rpc: ret, report)]
fn with_ret_report() -> Result<u32, MyError> { Ok(42) }

// string-literal component
#[instrument("block-producer": err)]
fn string_literal_component() -> Result<(), MyError> { Ok(()) }

// async fn – report/err read the declared return type, which is Result
#[instrument(rpc: report)]
async fn async_with_report() -> Result<(), MyError> { Ok(()) }

#[instrument(store: err)]
async fn async_with_err() -> Result<(), MyError> { Ok(()) }

fn main() {}
