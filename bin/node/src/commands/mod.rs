pub mod block_producer;
pub mod ntx_builder;
pub mod rpc;
pub mod store;
pub mod validator;

const ENV_DATA_DIRECTORY: &str = "MIDEN_NODE_DATA_DIRECTORY";
const ENV_ENABLE_OTEL: &str = "MIDEN_NODE_ENABLE_OTEL";
