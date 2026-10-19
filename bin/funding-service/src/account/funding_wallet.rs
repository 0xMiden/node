use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::domain::account::{AccountVaultDetails, StorageMapEntries};
use miden_node_proto::generated::miden::node::v1::GetAccountRequest as ProtoAccountRequest;
use miden_node_proto::generated::miden::node::v1::get_account_request::AccountDetailRequest;
use miden_node_proto::generated::miden::node::v1::get_account_request::account_detail_request::StorageRequest;
use miden_node_tracing::{miden_instrument, warn};
use miden_node_utils::retry::{self, RetryableWithContext};
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_objects::account_file::AccountFile;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorage,
    AccountType,
    StorageMap,
    StorageSlot,
    StorageSlotType,
};
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Nullifier;

use crate::COMPONENT;
mod deposits;
#[cfg(test)]
mod tests;

use deposits::spent_nullifiers;

/// The funding wallet's account state, signing key, and unspent deposits.
pub struct FundingWallet {
    account: Arc<Account>,
    secret_key: AuthSecretKey,
    fee_asset_id: AssetId,
    /// The first block to include in the next deposit and nullifier sync.
    next_sync: BlockNumber,
    deposits: HashMap<Nullifier, UsdcxP2Id>,
}

/// The account state and unspent deposits at a reference block, ready to apply to the wallet.
#[must_use = "the update must be applied to change the wallet"]
pub struct WalletUpdate {
    account: Account,
    deposits: HashMap<Nullifier, UsdcxP2Id>,
    block_num: BlockNumber,
}

impl FundingWallet {
    /// Loads the wallet and its signing key from an account file.
    pub fn load(path: &Path, fee_asset_id: AssetId) -> Result<Self> {
        let account_file = AccountFile::read(path)
            .with_context(|| format!("failed to read the account file at {}", path.display()))?;

        let secret_key = account_file.auth_secret_keys().first().cloned().with_context(|| {
            format!("the account file at {} holds no secret key", path.display())
        })?;

        let account = account_file.account();
        anyhow::ensure!(
            account.id().account_type() == AccountType::Public,
            "the funding account {} is not public: the service reads its state from the node, \
             which only stores the full state of a public account",
            account.id(),
        );

        Ok(Self {
            account: Arc::new(account.clone()),
            secret_key,
            fee_asset_id,
            next_sync: BlockNumber::GENESIS,
            deposits: HashMap::new(),
        })
    }

    pub fn account_id(&self) -> AccountId {
        self.account.id()
    }

    pub fn secret_key(&self) -> &AuthSecretKey {
        &self.secret_key
    }

    /// The unspent deposits discovered through the wallet's reference block.
    pub fn deposits(&self) -> &HashMap<Nullifier, UsdcxP2Id> {
        &self.deposits
    }

    /// Removes a consumed or rejected deposit from the wallet.
    pub fn remove_deposit(&mut self, nullifier: Nullifier) {
        self.deposits.remove(&nullifier);
    }

    /// Fetches an update to the specified block without changing the wallet.
    ///
    /// Retries transient RPC failures with backoff. Apply the returned update with [`Self::apply`].
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.wallet.sync_to",
        fields(account.id = self.account_id(), block.number = block_num),
        err,
    )]
    pub async fn sync_to(
        &self,
        rpc_client: &mut RpcClient,
        block_num: BlockNumber,
    ) -> Result<WalletUpdate> {
        let (_, result) = (|context| async move {
            let (wallet, rpc): (&Self, &mut RpcClient) = context;
            let result = wallet.sync_once(rpc, block_num).await;
            ((wallet, rpc), result)
        })
        .retry(retry::exponential(Duration::from_secs(1), Duration::from_secs(30)))
        .context((self, rpc_client))
        .when(|err| {
            err.downcast_ref::<tonic::Status>().is_some_and(|status| {
                matches!(
                    status.code(),
                    tonic::Code::Unavailable
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::ResourceExhausted
                )
            })
        })
        .notify(|err, delay| {
            warn!(
                err,
                target: COMPONENT,
                "Funding wallet synchronization failed; retrying after backoff",
                retry.delay_ms = delay.as_millis() as u64
            );
        })
        .await;
        result
    }

    async fn sync_once(
        &self,
        rpc_client: &mut RpcClient,
        block_num: BlockNumber,
    ) -> Result<WalletUpdate> {
        anyhow::ensure!(
            self.next_sync <= block_num + 1,
            "cannot sync the funding wallet to an earlier block",
        );
        let account = self.load_account_at(rpc_client, block_num).await?;
        let from = self.next_sync;
        let mut deposits = self.deposits.clone();
        deposits.extend(self.scan_deposits(rpc_client, from, block_num).await?);
        let nullifiers: Vec<_> = deposits.keys().copied().collect();
        let spent = spent_nullifiers(rpc_client, &nullifiers, from, block_num).await?;
        deposits.retain(|nullifier, _| !spent.contains(nullifier));
        Ok(WalletUpdate { account, deposits, block_num })
    }

    /// Applies the account state and deposits together after validating the update.
    pub fn apply(&mut self, update: WalletUpdate) -> Result<()> {
        anyhow::ensure!(
            update.account.id() == self.account_id(),
            "the update belongs to another wallet"
        );
        let next_sync = update.block_num + 1;
        anyhow::ensure!(
            self.next_sync <= next_sync,
            "cannot apply a wallet update from an earlier block",
        );
        let current_account = Arc::get_mut(&mut self.account)
            .context("cannot apply a wallet update while its account is in use")?;
        *current_account = update.account;
        self.deposits = update.deposits;
        self.next_sync = next_sync;
        Ok(())
    }

    /// Loads authenticated account state at the reference block.
    async fn load_account_at(
        &self,
        rpc_client: &mut RpcClient,
        block_num: BlockNumber,
    ) -> Result<Account> {
        let account_id = self.account_id();
        // A dummy commitment forces the server to return the vault.
        let dummy: miden_node_proto::generated::primitives::Word = Word::default().into();
        let request = ProtoAccountRequest {
            account_id: Some(account_id.into()),
            block_num: Some(block_num.into()),
            details: Some(AccountDetailRequest {
                code_commitment: Some(self.account.code().commitment().into()),
                asset_vault_commitment: Some(dummy),
                storage_request: Some(StorageRequest::AllStorageMaps(true)),
            }),
        };

        let response = rpc_client
            .get_account(request)
            .await
            .with_context(|| format!("failed to fetch account {account_id}"))?
            .into_inner();
        let response =
            response.decode_and_verify().context("failed to convert the account response")?;

        anyhow::ensure!(
            response.block_num == block_num,
            "the wallet response has the wrong reference block"
        );
        let witness = response.witness;
        anyhow::ensure!(
            witness.id() == account_id,
            "the account tree returned a witness for {} when {account_id} was requested",
            witness.id(),
        );

        let details = response
            .details
            .with_context(|| format!("no details returned for public account {account_id}"))?;

        if self.next_sync == BlockNumber::GENESIS {
            anyhow::ensure!(
                details.account_header.code_commitment() == self.account.code().commitment(),
                "the code of account {account_id} on chain does not match the account file: is the account file from another network?",
            );
        }
        let code = details.account_code.unwrap_or_else(|| self.account.code().clone());
        anyhow::ensure!(
            code.commitment() == details.account_header.code_commitment(),
            "the wallet code does not match its commitment at the reference block",
        );

        let vault = match details.vault_details {
            AccountVaultDetails::Assets(assets) => miden_protocol::asset::AssetVault::new(&assets)
                .context("failed to build the vault")?,
            AccountVaultDetails::LimitExceeded => {
                anyhow::bail!("account {account_id} holds too many assets to fetch in full")
            },
        };

        // Value slots come from the header, map slots from the map details.
        let mut map_entries = HashMap::new();
        for map_detail in details.storage_details.map_details {
            let StorageMapEntries::AllEntries(entries) = map_detail.entries else {
                anyhow::bail!("storage map {} was not returned in full", map_detail.slot_name);
            };
            map_entries.insert(map_detail.slot_name, entries);
        }

        let mut slots = Vec::new();
        for slot in details.storage_details.header.slots() {
            match slot.slot_type() {
                StorageSlotType::Value => {
                    slots.push(StorageSlot::with_value(slot.name().clone(), slot.value()));
                },
                StorageSlotType::Map => {
                    let entries = map_entries.remove(slot.name()).with_context(|| {
                        format!("no map entries returned for storage slot {}", slot.name())
                    })?;
                    let map = StorageMap::with_entries(entries)
                        .context("failed to build the storage map")?;
                    anyhow::ensure!(
                        map.root() == slot.value(),
                        "the storage map root for slot {} does not match the storage header",
                        slot.name()
                    );
                    slots.push(StorageSlot::with_map(slot.name().clone(), map));
                },
            }
        }
        let storage = AccountStorage::new(slots).context("failed to build the account storage")?;

        let account =
            Account::new(account_id, vault, storage, code, details.account_header.nonce(), None)
                .context("failed to build the account")?;

        // The witness and the details come from one response, so a mismatch means a bad
        // reconstruction.
        anyhow::ensure!(
            account.to_commitment() == witness.state_commitment(),
            "the reconstructed account {account_id} does not match its witness at block {block_num}",
        );

        Ok(account)
    }

    /// Returns the wallet's account state for execution.
    ///
    /// Execution must release its account reference before applying an update.
    pub fn account(&self) -> &Arc<Account> {
        &self.account
    }
}
