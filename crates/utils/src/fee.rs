use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::FeeParameters;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;

/// Derive a default, zero valued fee, payable to
/// [`miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET`].
///
/// # Panics
///
/// Panics if the test faucet account ID is invalid or if fee construction fails.
pub fn test_fee() -> FungibleAsset {
    let faucet = ACCOUNT_ID_FEE_FAUCET.try_into().unwrap();
    FungibleAsset::new(faucet, 0).unwrap()
}
/// Derive the default fee parameters, compatible with [`test_fee`].
///
/// # Panics
///
/// Panics if the test faucet account ID is invalid or if fee parameter construction fails.
pub fn test_fee_params() -> FeeParameters {
    let faucet = ACCOUNT_ID_FEE_FAUCET.try_into().unwrap();
    FeeParameters::new(faucet, 0).unwrap()
}
