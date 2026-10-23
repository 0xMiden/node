//! The status snapshot published by the funding worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_standards::account::faucets::FungibleFaucet;
use serde::{Deserialize, Serialize};

// NATIVE ASSET
// ================================================================================================

/// The metadata of the native asset, as the native faucet records it.
///
/// The native faucet cannot change these values, so the service reads them once at startup.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NativeAsset {
    /// The asset ID, in hexadecimal.
    asset_id: String,
    /// The token symbol.
    symbol: String,
    /// The number of decimal places of one token. It converts base units to tokens.
    decimals: u8,
    /// The token name.
    name: String,
}

impl NativeAsset {
    /// Reads the metadata of the asset with the given ID from the faucet which issues it.
    pub fn new(asset_id: AssetId, faucet: &FungibleFaucet) -> Self {
        Self {
            asset_id: asset_id.to_string(),
            symbol: faucet.symbol().to_string(),
            decimals: faucet.decimals(),
            name: faucet.token_name().as_str().to_owned(),
        }
    }
}

// STATUS SNAPSHOT
// ================================================================================================

/// The funding account's balance as of the last block read from the node.
///
/// The worker publishes the values, and the `Status` endpoint reads them. The two numbers are read
/// separately, so a concurrent update can pair a balance with the neighbouring block number. That
/// is acceptable for a status report and avoids taking a lock on the funding path.
#[derive(Clone)]
pub struct StatusSnapshot {
    account_id: AccountId,
    native_asset: NativeAsset,
    max_amount: u64,
    balance: Arc<AtomicU64>,
    chain_tip: Arc<AtomicU32>,
    verification_base_fee: Arc<AtomicU32>,
}

impl StatusSnapshot {
    /// Creates a snapshot for the given funding account.
    pub fn new(account_id: AccountId, native_asset: NativeAsset, max_amount: u64) -> Self {
        Self {
            account_id,
            native_asset,
            max_amount,
            balance: Arc::new(AtomicU64::new(0)),
            chain_tip: Arc::new(AtomicU32::new(0)),
            verification_base_fee: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Publishes the values read at `chain_tip`.
    pub fn update(&self, balance: u64, chain_tip: BlockNumber, verification_base_fee: u32) {
        self.balance.store(balance, Ordering::Relaxed);
        self.chain_tip.store(chain_tip.as_u32(), Ordering::Relaxed);
        self.verification_base_fee.store(verification_base_fee, Ordering::Relaxed);
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn native_asset(&self) -> &NativeAsset {
        &self.native_asset
    }

    pub fn max_amount(&self) -> u64 {
        self.max_amount
    }

    pub fn balance(&self) -> u64 {
        self.balance.load(Ordering::Relaxed)
    }

    pub fn chain_tip(&self) -> BlockNumber {
        self.chain_tip.load(Ordering::Relaxed).into()
    }

    pub fn verification_base_fee(&self) -> u32 {
        self.verification_base_fee.load(Ordering::Relaxed)
    }
}
