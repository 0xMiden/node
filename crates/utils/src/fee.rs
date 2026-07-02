use miden_protocol::block::FeeParameters;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;

/// Derive the default fee parameters, payable to
/// [`miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET`].
pub fn test_fee_params() -> FeeParameters {
    let faucet = ACCOUNT_ID_FEE_FAUCET.try_into().unwrap();
    FeeParameters::new(faucet, 0)
}
