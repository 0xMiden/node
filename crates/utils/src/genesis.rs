use std::fmt;
use std::path::Path;

use anyhow::Context;
use miden_node_persistence::miden_protobuf::ConversionError;
use miden_node_persistence::{PersistenceError, ProtobufValue, check_version};
use miden_protocol::block::{BlockNumber, SignedBlock};
use miden_protocol::protocol_config::ProtocolConfig;

/// A validated genesis block and its protocol configuration.
///
/// The block is the chain's trust root. Obtain it from a trusted source.
#[derive(Debug)]
pub struct GenesisBlock {
    block: SignedBlock,
    protocol_config: ProtocolConfig,
}

impl GenesisBlock {
    /// Validates the genesis block and its protocol configuration.
    pub fn new(block: SignedBlock, protocol_config: ProtocolConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            block.header().block_num() == BlockNumber::GENESIS,
            "expected genesis block number (0), got {}",
            block.header().block_num(),
        );
        anyhow::ensure!(
            block.signatures().is_empty(),
            "genesis block must not carry signatures, got {}",
            block.signatures().len(),
        );
        block.validate(None).context("genesis block validation failed")?;
        let expected = block.header().protocol_config_commitment();
        let actual = protocol_config.to_commitment();
        anyhow::ensure!(
            actual == expected,
            "genesis protocol configuration commitment mismatch: expected {expected}, got {actual}",
        );
        Ok(Self { block, protocol_config })
    }

    pub fn inner(&self) -> &SignedBlock {
        &self.block
    }

    /// Returns the block and discards the protocol configuration.
    pub fn into_inner(self) -> SignedBlock {
        self.block
    }

    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    pub fn into_parts(self) -> (SignedBlock, ProtocolConfig) {
        (self.block, self.protocol_config)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct InvalidGenesis(anyhow::Error);

impl ProtobufValue for GenesisBlock {
    type Message = miden_node_persistence::generated::GenesisFile;

    fn to_proto(&self) -> Self::Message {
        Self::Message {
            version: 1,
            block: Some(self.block.to_proto()),
            protocol_config: Some(self.protocol_config.to_proto()),
        }
    }

    fn from_proto(message: Self::Message) -> Result<Self, PersistenceError> {
        check_version("genesis file", message.version)?;
        let block =
            message.block.ok_or_else(|| ConversionError::message("missing genesis block"))?;
        let config = message
            .protocol_config
            .ok_or_else(|| ConversionError::message("missing genesis protocol configuration"))?;
        Self::new(SignedBlock::from_proto(block)?, ProtocolConfig::from_proto(config)?)
            .map_err(|error| ConversionError::new(InvalidGenesis(error)).into())
    }
}

/// Official Miden networks with a hosted genesis block.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialNetwork {
    Devnet,
    Testnet,
}

impl OfficialNetwork {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
        }
    }

    pub fn genesis_block_url(self) -> String {
        format!("https://genesis.{}.miden.io", self.as_str())
    }
}

impl fmt::Display for OfficialNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads a trusted genesis block and its protocol configuration from disk.
pub fn read_genesis_block(path: &Path) -> anyhow::Result<GenesisBlock> {
    let bytes = fs_err::read(path).context("failed to read genesis block file")?;
    deserialize_genesis_block(&bytes)
}

/// Downloads a trusted genesis block and its protocol configuration for an official Miden network.
pub async fn fetch_genesis_block(network: OfficialNetwork) -> anyhow::Result<GenesisBlock> {
    let url = network.genesis_block_url();
    let response = reqwest::get(url.as_str())
        .await
        .with_context(|| format!("failed to fetch genesis block from {url}"))?
        .error_for_status()
        .with_context(|| format!("failed to fetch genesis block from {url}"))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("failed to read genesis block response from {url}"))?;

    deserialize_genesis_block(&bytes)
}

fn deserialize_genesis_block(bytes: &[u8]) -> anyhow::Result<GenesisBlock> {
    miden_node_persistence::decode(bytes).context(
        "failed to deserialize genesis block and protocol configuration; regenerate genesis.dat with the current node",
    )
}

#[cfg(test)]
mod tests;
