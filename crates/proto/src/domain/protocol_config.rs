//! Protocol configuration validation at RPC boundaries.

use miden_protocol::block::BlockHeader;
use miden_protocol::protocol_config::ProtocolConfig;

use crate::decode::verify_value;
use crate::errors::ConversionError;
use crate::generated::protocol_config::ProtocolConfig as ProtoProtocolConfig;

/// Ensures protocol configuration is present and matches the protocol configuration commitment in
/// the header.
pub fn ensure_protocol_config_is_present_and_matches_header(
    config: Option<ProtoProtocolConfig>,
    header: &BlockHeader,
) -> Result<ProtocolConfig, ConversionError> {
    let config: ProtocolConfig = verify_value(
        "protocol_config",
        config.ok_or_else(|| ConversionError::message("protocol config is missing"))?,
    )?;
    let calculated = config.to_commitment();
    let expected = header.protocol_config_commitment();
    if calculated != expected {
        return Err(ConversionError::message(format!(
            "protocol config commitment {calculated} does not match header commitment {expected}"
        )));
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::AssetId;
    use miden_protocol::block::FeeParameters;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;

    use super::*;

    #[test]
    fn accepts_only_present_valid_matching_config() {
        let config = ProtocolConfig::current(AssetId::new_fungible(
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into().unwrap(),
        ))
        .unwrap();
        let other_header = BlockHeader::mock(0, None, None, &[]);
        let header = BlockHeader::new(
            Word::empty(),
            0.into(),
            Word::empty(),
            Word::empty(),
            Word::empty(),
            Word::empty(),
            Word::empty(),
            other_header.validator_config().clone(),
            FeeParameters::new(0),
            config.to_commitment(),
            None,
            0,
        );
        assert!(ensure_protocol_config_is_present_and_matches_header(None, &header).is_err());
        assert!(
            ensure_protocol_config_is_present_and_matches_header(
                Some(ProtoProtocolConfig::default()),
                &header
            )
            .is_err()
        );
        assert_eq!(
            ensure_protocol_config_is_present_and_matches_header(Some((&config).into()), &header)
                .unwrap(),
            config
        );
        assert!(
            ensure_protocol_config_is_present_and_matches_header(
                Some(config.into()),
                &other_header
            )
            .is_err()
        );
    }
}
