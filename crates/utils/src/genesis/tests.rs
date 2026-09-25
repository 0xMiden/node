use miden_node_persistence::encode;
use miden_node_persistence::prost::Message;
use miden_protocol::Word;
use miden_protocol::block::{
    BlockBody,
    BlockHeader,
    BlockSignatures,
    FeeParameters,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::transaction::OrderedTransactionHeaders;
use miden_protocol::utils::serde::{Deserializable, Serializable};

use super::*;

fn genesis(block_num: BlockNumber, config: &ProtocolConfig) -> SignedBlock {
    let body = BlockBody::new_unchecked(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let key = SigningKey::read_from_bytes(&[7; 32]).unwrap();
    let header = BlockHeader::new(
        Word::empty(),
        block_num,
        Word::empty(),
        Word::empty(),
        Word::empty(),
        body.compute_block_note_tree().root(),
        body.transactions().commitment(),
        ValidatorConfig::new(vec![key.public_key()], 1).unwrap(),
        FeeParameters::new(0),
        config.to_commitment(),
        None,
        0,
    );
    SignedBlock::new(header, body, BlockSignatures::new(Vec::new()).unwrap()).unwrap()
}

#[test]
fn genesis_round_trip_preserves_block_and_config() {
    let config = ProtocolConfig::mock();
    let block = genesis(BlockNumber::GENESIS, &config);
    let block_bytes = block.to_bytes();
    let genesis = GenesisBlock::new(block, config.clone()).unwrap();
    let bytes = encode(&genesis);

    // File downloads use the same decoder as local files.
    let decoded = deserialize_genesis_block(&bytes).unwrap();
    assert_eq!(decoded.inner().to_bytes(), block_bytes);
    assert_eq!(decoded.protocol_config(), &config);

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("genesis.dat");
    fs_err::write(&path, &bytes).unwrap();
    let from_file = read_genesis_block(&path).unwrap();
    let (block, stored_config) = from_file.into_parts();
    assert_eq!(block.to_bytes(), block_bytes);
    assert_eq!(stored_config, config);
}

#[test]
fn genesis_rejects_mismatched_config() {
    let config = ProtocolConfig::mock();
    let block = genesis(BlockNumber::GENESIS, &config);
    let other_config = ProtocolConfig::current(miden_protocol::asset::AssetId::new_fungible(
        miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1
            .try_into()
            .unwrap(),
    ))
    .unwrap();
    let bytes = miden_node_persistence::generated::GenesisFile {
        version: 1,
        block: Some(block.to_proto()),
        protocol_config: Some(other_config.to_proto()),
    }
    .encode_to_vec();
    let error = GenesisBlock::new(block, other_config).unwrap_err();
    assert!(error.to_string().contains("commitment mismatch"));
    assert!(deserialize_genesis_block(&bytes).is_err());
}

#[test]
fn genesis_rejects_non_genesis_and_signed_blocks() {
    let config = ProtocolConfig::mock();
    let block = genesis(BlockNumber::from(1), &config);
    let message = miden_node_persistence::generated::GenesisFile {
        version: 1,
        block: Some(block.to_proto()),
        protocol_config: Some(config.to_proto()),
    };
    assert!(deserialize_genesis_block(&message.encode_to_vec()).is_err());
    assert!(
        GenesisBlock::new(block, config.clone())
            .unwrap_err()
            .to_string()
            .contains("number")
    );

    let (header, body, _) = genesis(BlockNumber::GENESIS, &config).into_parts();
    let key = SigningKey::read_from_bytes(&[7; 32]).unwrap();
    let signatures = BlockSignatures::new(vec![key.sign(header.commitment())]).unwrap();
    let block = SignedBlock::new(header, body, signatures).unwrap();
    assert!(
        GenesisBlock::new(block, config)
            .unwrap_err()
            .to_string()
            .contains("must not carry signatures")
    );
}

#[test]
fn genesis_rejects_inconsistent_body() {
    let config = ProtocolConfig::mock();
    let header = BlockHeader::mock(BlockNumber::GENESIS, None, None, &[]);
    let (_, body, signatures) = genesis(BlockNumber::GENESIS, &config).into_parts();
    let block = SignedBlock::new_unchecked(header, body, signatures);
    assert!(
        GenesisBlock::new(block, config)
            .unwrap_err()
            .to_string()
            .contains("validation failed")
    );
}

#[test]
fn genesis_rejects_incomplete_malformed_and_trailing_data() {
    let config = ProtocolConfig::mock();
    let block = genesis(BlockNumber::GENESIS, &config);
    assert!(deserialize_genesis_block(&block.to_bytes()).is_err());
    assert!(deserialize_genesis_block(&[]).is_err());
    assert!(deserialize_genesis_block(&[0xff; 32]).is_err());
    let mut bytes = encode(&GenesisBlock::new(block, config).unwrap());
    assert!(deserialize_genesis_block(&bytes[..bytes.len() - 1]).is_err());
    bytes.push(0);
    assert!(deserialize_genesis_block(&bytes).is_err());
}

#[test]
fn genesis_file_is_versioned_protobuf() {
    use miden_node_persistence::generated::GenesisFile;
    use miden_node_persistence::prost::Message;
    let config = ProtocolConfig::mock();
    let value = GenesisBlock::new(genesis(BlockNumber::GENESIS, &config), config).unwrap();
    let message = GenesisFile::decode(encode(&value).as_slice()).unwrap();
    assert_eq!(message.version, 1);
    assert!(message.block.is_some());
    assert!(message.protocol_config.is_some());
}

#[test]
fn genesis_accepts_unknown_fields_and_rejects_versions() {
    let config = ProtocolConfig::mock();
    let value = GenesisBlock::new(genesis(BlockNumber::GENESIS, &config), config).unwrap();
    let mut bytes = encode(&value);
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    assert_eq!(deserialize_genesis_block(&bytes).unwrap().inner(), value.inner());
    for version in [0, 2] {
        let mut message = value.to_proto();
        message.version = version;
        assert!(deserialize_genesis_block(&message.encode_to_vec()).is_err());
    }
}

#[test]
fn genesis_rejects_missing_payload_fields() {
    let config = ProtocolConfig::mock();
    let value = GenesisBlock::new(genesis(BlockNumber::GENESIS, &config), config).unwrap();
    let mut message = value.to_proto();
    message.block = None;
    assert!(deserialize_genesis_block(&message.encode_to_vec()).is_err());
    let mut message = value.to_proto();
    message.protocol_config = None;
    assert!(deserialize_genesis_block(&message.encode_to_vec()).is_err());
}
