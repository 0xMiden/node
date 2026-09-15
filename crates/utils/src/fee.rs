use miden_protocol::block::FeeParameters;

/// Returns the default zero-fee parameters used by tests.
pub fn test_fee_params() -> FeeParameters {
    FeeParameters::new(0)
}

/// Returns the current protocol configuration with the standard testing faucet as its fee asset.
#[cfg(feature = "testing")]
pub fn test_protocol_config() -> miden_protocol::protocol_config::ProtocolConfig {
    use miden_protocol::asset::AssetId;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    let faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET
        .try_into()
        .expect("testing faucet account ID should be valid");
    miden_protocol::protocol_config::ProtocolConfig::current(AssetId::new_fungible(faucet_id))
        .expect("testing protocol configuration should be valid")
}
