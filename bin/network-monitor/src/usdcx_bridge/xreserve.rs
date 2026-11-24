//! Read-only client for the Circle xReserve contract that holds the collateral for `USDCx`.
//!
//! The client sends `eth_call` requests to a JSON-RPC endpoint of the chain that hosts the
//! contract. Errors never include the endpoint URL, because provider URLs often embed an API key.

use std::time::Duration;

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use miden_node_utils::http::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::status::XReserveDetails;

/// Contract functions read by the monitor.
mod abi {
    alloy_sol_types::sol! {
        function balanceOfNativeCollateral(address localToken, uint32 remoteDomain)
            external view returns (uint256);
        function paused() external view returns (bool);
        function domainDepositsPaused(uint32 domain) external view returns (bool);
        function domainWithdrawalsPaused(uint32 domain) external view returns (bool);
        function decimals() external view returns (uint8);
    }
}

/// Maximum number of bytes of an unsuccessful response body included in an error.
const MAX_ERROR_BODY_LEN: usize = 256;

/// Reads the xReserve contract through a JSON-RPC endpoint.
pub struct XReserveClient {
    http: Client,
    url: Url,
    address: Address,
    local_token: Address,
    timeout: Duration,
    /// Chain ID and collateral token decimals, which do not change once read.
    chain: Option<(u64, u8)>,
}

impl XReserveClient {
    pub fn new(url: Url, address: Address, local_token: Address, timeout: Duration) -> Self {
        Self {
            http: Client::new(),
            url,
            address,
            local_token,
            timeout,
            chain: None,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// Reads the collateral and pause flags for `domain`.
    ///
    /// The collateral is read first, so it is as close as possible to the faucet read that
    /// precedes this call.
    pub async fn read(&mut self, domain: u32) -> Result<XReserveDetails> {
        let collateral = self
            .call(
                self.address,
                &abi::balanceOfNativeCollateralCall {
                    localToken: self.local_token,
                    remoteDomain: domain,
                },
            )
            .await
            .context("failed to read the collateral")?;
        let collateral = collateral_to_u64(collateral)?;
        let paused = self
            .call(self.address, &abi::pausedCall {})
            .await
            .context("failed to read the global pause flag")?;
        let deposits_paused = self
            .call(self.address, &abi::domainDepositsPausedCall { domain })
            .await
            .context("failed to read the deposit pause flag")?;
        let withdrawals_paused = self
            .call(self.address, &abi::domainWithdrawalsPausedCall { domain })
            .await
            .context("failed to read the withdrawal pause flag")?;
        let (chain_id, collateral_decimals) = self.chain().await?;

        Ok(XReserveDetails {
            chain_id,
            collateral,
            collateral_decimals,
            paused,
            deposits_paused,
            withdrawals_paused,
        })
    }

    /// Returns the chain ID and the decimals of the collateral token, reading them on first use.
    async fn chain(&mut self) -> Result<(u64, u8)> {
        if let Some(chain) = self.chain {
            return Ok(chain);
        }
        let chain_id = self.request("eth_chainId", json!([])).await?;
        let chain_id = parse_quantity(&chain_id).context("failed to read the chain ID")?;
        let decimals = self
            .call(self.local_token, &abi::decimalsCall {})
            .await
            .context("failed to read the collateral token decimals")?;
        self.chain = Some((chain_id, decimals));
        Ok((chain_id, decimals))
    }

    /// Calls a view function of the contract at `to` on the latest block.
    async fn call<C: SolCall>(&self, to: Address, call: &C) -> Result<C::Return> {
        let data = format!("0x{}", hex::encode(call.abi_encode()));
        let result = self
            .request("eth_call", json!([{ "to": to.to_string(), "data": data }, "latest"]))
            .await?;
        let bytes = parse_data(&result)?;
        anyhow::ensure!(!bytes.is_empty(), "the call returned no data; is {to} a contract?");
        C::abi_decode_returns(&bytes).context("failed to decode the call result")
    }

    /// Sends a JSON-RPC request and returns its string result.
    async fn request(&self, method: &str, params: Value) -> Result<String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response = self
            .http
            .post(self.url.clone())
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
            .map_err(miden_node_utils::http::Error::without_url)?;
        let status = response.status();
        let body = response.text().await.map_err(miden_node_utils::http::Error::without_url)?;
        anyhow::ensure!(status.is_success(), "HTTP {status}: {}", truncate(&body));

        let response: JsonRpcResponse = serde_json::from_str(&body)
            .with_context(|| format!("invalid JSON-RPC response: {}", truncate(&body)))?;
        match (response.result, response.error) {
            (_, Some(error)) => Err(error.into()),
            (Some(Value::String(result)), None) => Ok(result),
            (Some(result), None) => anyhow::bail!("unexpected JSON-RPC result: {result}"),
            (None, None) => anyhow::bail!("the JSON-RPC response has no result"),
        }
    }
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)?;
        if let Some(data) = &self.data {
            write!(f, " ({data})")?;
        }
        Ok(())
    }
}

impl std::error::Error for JsonRpcError {}

/// Converts the collateral to `u64`, the integer type of Miden asset amounts.
fn collateral_to_u64(collateral: U256) -> Result<u64> {
    u64::try_from(collateral).map_err(|_| {
        anyhow::anyhow!("the collateral {collateral} does not fit in a Miden asset amount")
    })
}

/// Decodes a `0x`-prefixed hex data string.
fn parse_data(value: &str) -> Result<Vec<u8>> {
    let hex = value.strip_prefix("0x").context("the call result is not 0x-prefixed")?;
    hex::decode(hex).context("the call result is not valid hex")
}

/// Decodes a `0x`-prefixed hex quantity.
fn parse_quantity(value: &str) -> Result<u64> {
    let hex = value.strip_prefix("0x").context("the quantity is not 0x-prefixed")?;
    u64::from_str_radix(hex, 16).context("the quantity is not a valid hex number")
}

fn truncate(body: &str) -> &str {
    let mut end = body.len().min(MAX_ERROR_BODY_LEN);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use alloy_primitives::address;
    use axum::Router;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;

    use super::*;

    const XRESERVE: Address = address!("0x008888878f94C0d87defdf0B07f46B93C1934442");
    const USDC: Address = address!("0x3600000000000000000000000000000000000000");
    const MIDEN_DOMAIN: u32 = 10_007;
    /// A path segment standing in for a provider API key.
    const SECRET: &str = "secret-api-key";

    /// Contract state served by the stub, or a fixed failure.
    #[derive(Clone)]
    enum Stub {
        Contract {
            collateral: U256,
            paused: bool,
            deposits_paused: bool,
            withdrawals_paused: bool,
        },
        RpcError,
        Http(StatusCode),
        Malformed,
        EmptyResult,
    }

    impl Stub {
        fn healthy() -> Self {
            Stub::Contract {
                collateral: U256::from(47_342_363_254_u64),
                paused: false,
                deposits_paused: false,
                withdrawals_paused: true,
            }
        }
    }

    /// Answers JSON-RPC requests like an xReserve chain node. Calls for a domain or token other
    /// than Miden's revert, as the contract does for unregistered ones.
    async fn handle(State(stub): State<Arc<Mutex<Stub>>>, body: String) -> Response {
        let stub = stub.lock().unwrap().clone();
        let request: Value = serde_json::from_str(&body).unwrap();
        let result = match stub {
            Stub::Http(status) => return (status, "rate limited").into_response(),
            Stub::Malformed => return "not json".into_response(),
            Stub::RpcError => {
                return axum::Json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": { "code": 3, "message": "execution reverted", "data": "0x87f4e921" }
                }))
                .into_response();
            },
            Stub::EmptyResult => "0x".to_string(),
            Stub::Contract {
                collateral,
                paused,
                deposits_paused,
                withdrawals_paused,
            } => match request["method"].as_str().unwrap() {
                "eth_chainId" => "0x4cef52".to_string(),
                "eth_call" => {
                    let call = &request["params"][0];
                    let to: Address = call["to"].as_str().unwrap().parse().unwrap();
                    let data = parse_data(call["data"].as_str().unwrap()).unwrap();
                    let returned = match (to, &data[..4]) {
                        (XRESERVE, selector)
                            if selector == abi::balanceOfNativeCollateralCall::SELECTOR =>
                        {
                            let call =
                                abi::balanceOfNativeCollateralCall::abi_decode(&data).unwrap();
                            if call.localToken != USDC || call.remoteDomain != MIDEN_DOMAIN {
                                return axum::Json(json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "error": { "code": 3, "message": "execution reverted" }
                                }))
                                .into_response();
                            }
                            abi::balanceOfNativeCollateralCall::abi_encode_returns(&collateral)
                        },
                        (XRESERVE, selector) if selector == abi::pausedCall::SELECTOR => {
                            abi::pausedCall::abi_encode_returns(&paused)
                        },
                        (XRESERVE, selector)
                            if selector == abi::domainDepositsPausedCall::SELECTOR =>
                        {
                            abi::domainDepositsPausedCall::abi_encode_returns(&deposits_paused)
                        },
                        (XRESERVE, selector)
                            if selector == abi::domainWithdrawalsPausedCall::SELECTOR =>
                        {
                            abi::domainWithdrawalsPausedCall::abi_encode_returns(
                                &withdrawals_paused,
                            )
                        },
                        (USDC, selector) if selector == abi::decimalsCall::SELECTOR => {
                            abi::decimalsCall::abi_encode_returns(&6)
                        },
                        _ => Vec::new(),
                    };
                    format!("0x{}", hex::encode(returned))
                },
                method => panic!("unexpected method {method}"),
            },
        };
        axum::Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })).into_response()
    }

    /// Serves `stub` and returns a client whose URL path holds [`SECRET`].
    async fn serve(stub: Stub) -> (XReserveClient, Arc<Mutex<Stub>>) {
        let stub = Arc::new(Mutex::new(stub));
        let app = Router::new().route("/{key}", post(handle)).with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            Url::parse(&format!("http://{}/{SECRET}", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (XReserveClient::new(url, XRESERVE, USDC, Duration::from_secs(5)), stub)
    }

    #[tokio::test]
    async fn reads_collateral_and_pause_flags_for_the_domain() {
        let (mut client, _) = serve(Stub::healthy()).await;

        let state = client.read(MIDEN_DOMAIN).await.unwrap();

        assert_eq!(
            state,
            XReserveDetails {
                chain_id: 5_042_002,
                collateral: 47_342_363_254,
                collateral_decimals: 6,
                paused: false,
                deposits_paused: false,
                withdrawals_paused: true,
            }
        );
    }

    #[tokio::test]
    async fn unregistered_domain_is_an_error() {
        let (mut client, _) = serve(Stub::healthy()).await;

        let err = format!("{:#}", client.read(10_003).await.unwrap_err());

        assert!(err.contains("execution reverted"), "got: {err}");
    }

    #[tokio::test]
    async fn failed_requests_are_errors_without_the_url() {
        let cases = [
            (Stub::RpcError, "execution reverted"),
            (Stub::Http(StatusCode::TOO_MANY_REQUESTS), "429"),
            (Stub::Malformed, "invalid JSON-RPC response"),
            (Stub::EmptyResult, "returned no data"),
        ];
        for (stub, expected) in cases {
            let (mut client, _) = serve(stub).await;

            let err = format!("{:#}", client.read(MIDEN_DOMAIN).await.unwrap_err());

            assert!(err.contains(expected), "expected {expected:?}, got: {err}");
            assert!(!err.contains(SECRET), "the error leaks the URL: {err}");
        }
    }

    #[tokio::test]
    async fn unreachable_endpoint_error_does_not_include_the_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url =
            Url::parse(&format!("http://{}/{SECRET}", listener.local_addr().unwrap())).unwrap();
        drop(listener);
        let mut client = XReserveClient::new(url, XRESERVE, USDC, Duration::from_secs(5));

        let err = format!("{:#}", client.read(MIDEN_DOMAIN).await.unwrap_err());

        assert!(!err.contains(SECRET), "the error leaks the URL: {err}");
    }

    #[tokio::test]
    async fn collateral_beyond_asset_amounts_is_an_error() {
        let stub = Stub::Contract {
            collateral: U256::from(u64::MAX) + U256::from(1),
            paused: false,
            deposits_paused: false,
            withdrawals_paused: false,
        };
        let (mut client, _) = serve(stub).await;

        let err = format!("{:#}", client.read(MIDEN_DOMAIN).await.unwrap_err());

        assert!(err.contains("does not fit"), "got: {err}");
    }

    #[tokio::test]
    async fn recovers_after_a_failed_read() {
        let (mut client, stub) = serve(Stub::Http(StatusCode::BAD_GATEWAY)).await;
        assert!(client.read(MIDEN_DOMAIN).await.is_err());

        *stub.lock().unwrap() = Stub::healthy();

        assert_eq!(client.read(MIDEN_DOMAIN).await.unwrap().collateral, 47_342_363_254);
    }
}
