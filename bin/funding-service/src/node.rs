//! Node access.

use std::collections::{HashMap, HashSet};
use std::error::Error as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use backon::ExponentialBuilder;
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::account::{AccountVaultDetails, StorageMapEntries};
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::rpc::account_request::AccountDetailRequest;
use miden_node_proto::generated::rpc::{
    AccountRequest as ProtoAccountRequest,
    BlockHeaderByNumberRequest,
    BlockRange,
    FinalityLevel,
    NotesByIdRequest,
    SyncChainMmrRequest,
    SyncNotesRequest,
    SyncNullifiersRequest,
    SyncTransactionsRequest,
};
use miden_node_proto::generated::submission::ProvenTransactionSubmission;
use miden_node_proto::{DecodeMessageExt, VerifyWith};
use miden_node_tracing::warn;
use miden_node_utils::limiter::{
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_node_utils::retry::Retryable;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountStorage,
    StorageMap,
    StorageSlot,
    StorageSlotType,
};
use miden_protocol::asset::{AssetId, AssetVault};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber, FeeParameters};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::note::{Note, NoteId, NoteTag, Nullifier};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{PartialBlockchain, ProvenTransaction, TransactionId};
use tokio::sync::Mutex;
use url::Url;

use crate::COMPONENT;
use crate::deposit::is_deposit;

#[cfg(test)]
pub(crate) mod tests;

// RPC NODE CLIENT
// ================================================================================================

/// Reads chain state from the node's RPC API and submits transactions to it.
#[derive(Clone)]
pub struct RpcNodeClient {
    rpc_client: RpcClient,
    genesis_commitment: Word,
    protocol_config: ProtocolConfig,
    trusted_validator_signing_keys: Arc<[ValidatorPublicKey]>,
    sealer: Arc<Mutex<Option<TransactionInputsSealer>>>,
}

impl RpcNodeClient {
    /// Connects to the node's RPC API and verifies the attested transaction encryption key.
    pub async fn connect(
        rpc_url: &Url,
        timeout: Duration,
        trusted_validator_signing_keys: Vec<ValidatorPublicKey>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !trusted_validator_signing_keys.is_empty(),
            "at least one trusted validator signing key is required to verify the transaction \
             encryption key",
        );

        let (rpc_client, genesis_commitment, protocol_config) =
            create_genesis_aware_rpc_client(rpc_url, timeout).await?;

        let client = Self {
            rpc_client,
            genesis_commitment,
            protocol_config,
            trusted_validator_signing_keys: Arc::from(trusted_validator_signing_keys),
            sealer: Arc::new(Mutex::new(None)),
        };
        // Fetch and verify the encryption key eagerly so an untrusted key fails at startup.
        client.sealer().await?;

        Ok(client)
    }

    /// The commitment of the genesis block the node serves. It identifies the chain.
    pub fn genesis_commitment(&self) -> Word {
        self.genesis_commitment
    }

    /// The protocol configuration the genesis block commits to.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// The fee parameters of `block_num`, or at the chain tip when it is `None`.
    pub async fn fee_parameters(&self, block_num: Option<BlockNumber>) -> Result<FeeParameters> {
        let header = fetch_block_header(&mut self.rpc_client.clone(), block_num).await?;

        Ok(header.fee_parameters().clone())
    }

    /// The asset vault of a public account, with the block number the node observed it at.
    pub async fn public_account_vault(
        &self,
        account_id: AccountId,
    ) -> Result<(AssetVault, BlockNumber)> {
        // A dummy commitment never matches the vault root, which makes the node return the vault in
        // full. Code and storage are not requested.
        let dummy = Word::default().into();
        let request = ProtoAccountRequest {
            account_id: Some(account_id.into()),
            // Without a block number the node answers at its chain tip.
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: Some(dummy),
                storage_request: None,
            }),
        };

        let response = self
            .rpc_client
            .clone()
            .get_account(request)
            .await
            .with_context(|| format!("failed to fetch account {account_id}"))?
            .into_inner();
        let response =
            response.decode_and_verify().context("failed to convert the account response")?;

        let details = response
            .details
            .with_context(|| format!("no details returned for public account {account_id}"))?;

        let vault = match details.vault_details {
            AccountVaultDetails::Assets(assets) => {
                AssetVault::new(&assets).context("failed to build the vault")?
            },
            AccountVaultDetails::LimitExceeded => {
                anyhow::bail!("account {account_id} holds too many assets to fetch in full")
            },
        };

        Ok((vault, response.block_num))
    }

    /// The committed chain tip header with a partial blockchain which proves it.
    pub async fn tip_chain_state(&self) -> Result<(BlockHeader, PartialBlockchain)> {
        fetch_tip_chain_state(&mut self.rpc_client.clone(), self.genesis_commitment).await
    }

    /// A public account in full with its account-tree witness at `block_num`.
    pub async fn public_account(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<(Account, AccountWitness)> {
        fetch_public_account(&mut self.rpc_client.clone(), account_id, block_num).await
    }

    /// Returns one page of deposits and the last block checked in the given range.
    pub async fn sync_deposits(
        &self,
        funder: AccountId,
        fee_asset_id: AssetId,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> Result<SyncedDeposits> {
        let response = self
            .rpc_client
            .clone()
            .sync_notes(SyncNotesRequest {
                block_range: Some(BlockRange {
                    block_from: from_block.as_u32(),
                    block_to: to_block.as_u32(),
                }),
                note_tags: vec![NoteTag::with_account_target(funder).as_u32()],
            })
            .await
            .context("failed to synchronize notes")?
            .into_inner();

        let last_checked_block: BlockNumber = response
            .pagination_info
            .context("the sync_notes response did not include pagination information")?
            .block_num
            .into();
        anyhow::ensure!(
            (from_block..=to_block).contains(&last_checked_block),
            "the node answered a note scan from {from_block} to {to_block} with block {last_checked_block}",
        );

        let mut note_ids = Vec::new();
        for block in response.blocks {
            for record in block.notes {
                let proof = record
                    .inclusion_proof
                    .context("a note sync record did not include an inclusion proof")?;
                let note_id = proof
                    .note_id
                    .context("a note inclusion proof did not include a note ID")?
                    .decode_and_verify()
                    .context("failed to verify a synced note ID")?;
                note_ids.push(note_id);
            }
        }

        let deposits = self
            .get_public_notes_by_id(&note_ids)
            .await?
            .into_iter()
            .filter(|note| is_deposit(note, funder, fee_asset_id))
            .collect();

        Ok(SyncedDeposits { deposits, last_checked_block })
    }

    /// The notes among `note_ids` whose details the node stores.
    async fn get_public_notes_by_id(&self, note_ids: &[NoteId]) -> Result<Vec<Note>> {
        let mut notes = Vec::new();

        // The node rejects a request which asks for more note IDs than it accepts, so the IDs are
        // requested in chunks of the limit it enforces.
        for chunk in note_ids.chunks(QueryParamNoteIdLimit::LIMIT) {
            let note_ids = chunk.iter().map(|note_id| note_id.as_word().into()).collect();

            let response = self
                .rpc_client
                .clone()
                .get_notes_by_id(NotesByIdRequest { note_ids })
                .await
                .context("failed to fetch notes from RPC")?
                .into_inner();

            for committed in response.notes {
                let Some(note) = committed.note else {
                    continue;
                };
                if note.note_details.is_none() {
                    continue;
                }

                let note = note.decode_and_verify().context("failed to verify a committed note")?;
                notes.push(note);
            }
        }

        Ok(notes)
    }

    /// Returns the requested nullifiers spent from genesis through `tip`.
    pub async fn spent_nullifiers(
        &self,
        nullifiers: &[Nullifier],
        tip: BlockNumber,
    ) -> Result<HashSet<Nullifier>> {
        let requested: HashSet<_> = nullifiers.iter().copied().collect();
        let mut prefixes: Vec<_> = nullifiers.iter().map(|n| u32::from(n.prefix())).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        let mut spent = HashSet::new();

        for chunk in prefixes.chunks(QueryParamNullifierPrefixLimit::LIMIT) {
            let mut start = BlockNumber::GENESIS;
            loop {
                let response = self
                    .rpc_client
                    .clone()
                    .sync_nullifiers(SyncNullifiersRequest {
                        block_range: Some(BlockRange {
                            block_from: start.as_u32(),
                            block_to: tip.as_u32(),
                        }),
                        prefix_len: 16,
                        nullifiers: chunk.to_vec(),
                    })
                    .await
                    .context("failed to synchronize nullifiers")?
                    .into_inner()
                    .decode_and_verify()
                    .context("failed to convert the nullifier sync response")?;

                let last_checked = response.pagination_info.block_num;
                anyhow::ensure!(
                    (start..=tip).contains(&last_checked),
                    "the node answered a nullifier scan from {start} to {tip} with block {last_checked}",
                );
                for nullifier in response.nullifiers.into_keys() {
                    // Prefix matches can include nullifiers that were not requested.
                    if requested.contains(&nullifier) {
                        spent.insert(nullifier);
                    }
                }
                if last_checked == tip {
                    break;
                }
                start = last_checked + 1;
            }
        }

        Ok(spent)
    }

    /// Checks for commitment before reporting expiration. Reads every page in the block range.
    pub async fn transaction_status(
        &self,
        account_id: AccountId,
        transaction_id: TransactionId,
        reference_block: BlockNumber,
        expiration_block: BlockNumber,
    ) -> Result<TransactionStatus> {
        let tip = self.committed_tip().await?;
        let end = tip.min(expiration_block);
        let mut start = reference_block + 1;

        while start <= end {
            let response = self
                .rpc_client
                .clone()
                .sync_transactions(SyncTransactionsRequest {
                    block_range: Some(BlockRange {
                        block_from: start.as_u32(),
                        block_to: end.as_u32(),
                    }),
                    account_ids: vec![account_id.into()],
                })
                .await
                .context("failed to synchronize transactions")?
                .into_inner();

            for record in response.transactions {
                let id = record
                    .header
                    .context("a transaction record did not include a header")?
                    .transaction_id
                    .context("a transaction header did not include an ID")?
                    .decode_and_verify()
                    .context("failed to convert a transaction ID")?;
                if id == transaction_id {
                    return Ok(TransactionStatus::Committed);
                }
            }

            let last_checked: BlockNumber = response
                .pagination_info
                .context("the sync_transactions response did not include pagination information")?
                .block_num
                .into();
            anyhow::ensure!(
                (start..=end).contains(&last_checked),
                "the node answered a transaction scan from {start} to {end} with block {last_checked}",
            );
            if last_checked == end {
                break;
            }
            start = last_checked + 1;
        }

        Ok(if tip >= expiration_block {
            TransactionStatus::Expired
        } else {
            TransactionStatus::Pending
        })
    }

    /// The chain tip of the node's local store.
    pub async fn committed_tip(&self) -> Result<BlockNumber> {
        let status = self
            .rpc_client
            .clone()
            .status(())
            .await
            .context("failed to fetch the node status")?
            .into_inner();

        Ok(status.chain_tip.into())
    }

    /// Seals and submits one proven transaction. Errors occur before submission starts.
    pub async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        transaction_inputs: &[u8],
    ) -> Result<SubmissionOutcome> {
        let sealed = self
            .sealer()
            .await?
            .seal(proven_tx.id(), transaction_inputs)
            .context("failed to seal the transaction inputs")?;
        let request = ProvenTransactionSubmission {
            transaction: Some(proven_tx.into()),
            sealed_transaction_inputs: Some(sealed),
        };
        let result = self.rpc_client.clone().submit_proven_tx(request).await;

        if result.is_err() {
            // The encryption key can be stale. Fetch it again for the next submission.
            *self.sealer.lock().await = None;
        }

        Ok(match result {
            Ok(_) => SubmissionOutcome::Accepted,
            Err(status) => SubmissionOutcome::from_status(status),
        })
    }

    /// The cached verified sealer. The attested key is fetched and checked on first use.
    async fn sealer(&self) -> Result<TransactionInputsSealer> {
        if let Some(sealer) = self.sealer.lock().await.clone() {
            return Ok(sealer);
        }

        let key = self
            .rpc_client
            .clone()
            .get_transaction_encryption_key(())
            .await
            .context("failed to fetch the transaction encryption key")?
            .into_inner();
        let verified = key
            .verify_with(TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_signing_keys,
            ))
            .context("untrusted transaction encryption key")?;
        let sealer = TransactionInputsSealer::new(verified);

        let mut cached = self.sealer.lock().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }
        *cached = Some(sealer.clone());
        Ok(sealer)
    }
}

/// Whether the node accepted, rejected, or might have received the submission.
#[derive(Debug)]
pub enum SubmissionOutcome {
    Accepted,
    Rejected(tonic::Status),
    Unknown(tonic::Status),
}

impl SubmissionOutcome {
    fn from_status(status: tonic::Status) -> Self {
        // The error byte identifies a node rejection. Without it, these codes can also report
        // transport or response-decoding failures after the node accepted the transaction.
        let unknown = status.source().is_some()
            || (status.details().len() != 1
                && matches!(
                    status.code(),
                    tonic::Code::Cancelled
                        | tonic::Code::Unknown
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::Internal
                        | tonic::Code::Unavailable
                        | tonic::Code::DataLoss
                ));
        if unknown {
            Self::Unknown(status)
        } else {
            Self::Rejected(status)
        }
    }
}

/// The outcome of a transaction at the committed chain tip.
#[derive(Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Committed,
    Expired,
}

/// The result of one deposit synchronization.
pub struct SyncedDeposits {
    /// The matching deposits. These notes can already be spent.
    pub deposits: Vec<Note>,
    /// The last block the node checked. The next scan starts after it.
    pub last_checked_block: BlockNumber,
}

// RPC HELPERS
// ================================================================================================

/// Backoff for the genesis-discovery handshake, so a node which is still starting does not abort
/// the service.
const GENESIS_DISCOVERY_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const GENESIS_DISCOVERY_BACKOFF_MAX: Duration = Duration::from_secs(30);
const GENESIS_DISCOVERY_MAX_RETRIES: usize = 10;

fn genesis_discovery_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(GENESIS_DISCOVERY_BACKOFF_INITIAL)
        .with_max_delay(GENESIS_DISCOVERY_BACKOFF_MAX)
        .with_factor(2.0)
        .with_max_times(GENESIS_DISCOVERY_MAX_RETRIES)
        .with_jitter()
}

/// Creates an RPC client configured with the correct genesis metadata in the `Accept` header so
/// that write RPCs such as `SubmitProvenTx` are accepted by the node.
async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<(RpcClient, Word, ProtocolConfig)> {
    (|| async {
        // First, create a temporary client without genesis metadata to discover the genesis block
        // header and its commitment.
        let mut rpc: RpcClient = Builder::new(rpc_url.clone())
            .with_tls()
            .context("failed to configure TLS for the RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_auth_header()
            .with_otel_context_injection()
            .connect()
            .await
            .context("failed to create an RPC client for genesis discovery")?;

        let (genesis_header, protocol_config) = fetch_genesis_header_and_config(&mut rpc).await?;
        let genesis_commitment = genesis_header.commitment();

        // Rebuild the client, this time including the required genesis metadata so that write RPCs
        // like SubmitProvenTx are accepted by the node.
        let rpc_client = Builder::new(rpc_url.clone())
            .with_tls()
            .context("failed to configure TLS for the RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment)
            .without_auth_header()
            .with_otel_context_injection()
            .connect()
            .await
            .context("failed to connect to the RPC server with genesis metadata")?;

        Ok((rpc_client, genesis_commitment, protocol_config))
    })
    .retry(genesis_discovery_backoff())
    .notify(|err: &anyhow::Error, sleep: Duration| {
        warn!(
            err,
            target: COMPONENT,
            "RPC genesis discovery failed; retrying after backoff",
            retry.delay_ms = sleep.as_millis() as u64
        );
    })
    .await
}

/// Fetches a block header from RPC.
async fn fetch_block_header(
    rpc_client: &mut RpcClient,
    block_num: Option<BlockNumber>,
) -> Result<BlockHeader> {
    let request = BlockHeaderByNumberRequest {
        block_num: block_num.map(|block_num| block_num.as_u32()),
        include_mmr_proof: None,
        include_protocol_config: None,
    };

    let response = rpc_client
        .get_block_header_by_number(request)
        .await
        .context("failed to get the block header from RPC")?;

    let block_header = response
        .into_inner()
        .block_header
        .context("the block header response holds no header")?;

    block_header
        .decode_and_build_unchecked()
        .context("failed to build the block header")
}

/// Fetches the genesis block header and the protocol configuration it commits to.
///
/// The commitment of the returned configuration is checked against the header, so a configuration
/// which names an asset the chain does not use is rejected.
async fn fetch_genesis_header_and_config(
    rpc_client: &mut RpcClient,
) -> Result<(BlockHeader, ProtocolConfig)> {
    let response = rpc_client
        .get_block_header_by_number(BlockHeaderByNumberRequest {
            block_num: Some(BlockNumber::GENESIS.as_u32()),
            include_mmr_proof: None,
            include_protocol_config: Some(true),
        })
        .await
        .context("failed to get the genesis block header from RPC")?
        .into_inner();

    let block_header: BlockHeader = response
        .block_header
        .context("the block header response holds no header")?
        .decode_and_build_unchecked()
        .context("failed to build the block header")?;

    let protocol_config = ensure_protocol_config_is_present_and_matches_header(
        response.protocol_config,
        &block_header,
    )
    .context("the node served an invalid protocol configuration")?;

    Ok((block_header, protocol_config))
}

/// Fetches the chain tip header together with a [`PartialBlockchain`] whose peaks hash to that
/// header's chain commitment, making the pair usable as a transaction reference block.
async fn fetch_tip_chain_state(
    rpc_client: &mut RpcClient,
    genesis_commitment: Word,
) -> Result<(BlockHeader, PartialBlockchain)> {
    let response = rpc_client
        .sync_chain_mmr(SyncChainMmrRequest {
            // The MMR is seeded with the genesis block below, so the delta starts at block 1.
            current_client_block_height: BlockNumber::GENESIS.as_u32(),
            finality_level: FinalityLevel::Committed.into(),
        })
        .await
        .context("failed to sync the chain MMR")?
        .into_inner();

    let tip_header: BlockHeader = response
        .block_header
        .context("the sync_chain_mmr response did not include a block header")?
        .decode_and_build_unchecked()
        .context("failed to build the sync target block header")?;

    let delta: MmrDelta = response
        .mmr_delta
        .context("the sync_chain_mmr response did not include an MMR delta")?
        .decode_and_verify()
        .context("failed to verify the MMR delta")?;

    let mut mmr = PartialMmr::from_peaks(
        MmrPeaks::new(Forest::new(0).context("an empty forest should be valid")?, Vec::new())
            .context("empty MMR peaks should be valid")?,
    );

    if tip_header.block_num() != BlockNumber::GENESIS {
        mmr.add(genesis_commitment, false)
            .context("failed to seed the MMR with the genesis block")?;
        mmr.apply(delta).context("failed to apply the MMR delta")?;
    }

    anyhow::ensure!(
        mmr.peaks().hash_peaks() == tip_header.chain_commitment(),
        "the synced MMR peaks do not match the chain commitment of block {}",
        tip_header.block_num()
    );

    let blockchain = PartialBlockchain::new(mmr, Vec::new())
        .context("failed to build the partial blockchain")?;

    Ok((tip_header, blockchain))
}

/// Fetches a public account in full, with code, vault and storage maps, plus its account-tree
/// witness at the given block.
async fn fetch_public_account(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<(Account, AccountWitness)> {
    use miden_node_proto::generated::rpc::account_request::AccountDetailRequest;
    use miden_node_proto::generated::rpc::account_request::account_detail_request::StorageRequest;

    // Dummy commitments force the server to include code and vault data in the response.
    let dummy: miden_node_proto::generated::primitives::Word = Word::default().into();
    let request = ProtoAccountRequest {
        account_id: Some(account_id.into()),
        block_num: Some(block_num.into()),
        details: Some(AccountDetailRequest {
            code_commitment: Some(dummy.clone()),
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

    let witness = response.witness;
    anyhow::ensure!(
        witness.id() == account_id,
        "the account tree returned a witness for {} when {account_id} was requested",
        witness.id(),
    );

    let details = response
        .details
        .with_context(|| format!("no details returned for public account {account_id}"))?;

    let code = details.account_code.context("the server did not return the account code")?;

    let vault = match details.vault_details {
        AccountVaultDetails::Assets(assets) => {
            miden_protocol::asset::AssetVault::new(&assets).context("failed to build the vault")?
        },
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
                let map =
                    StorageMap::with_entries(entries).context("failed to build the storage map")?;
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

    // The witness and the details come from one response, so a mismatch means a bad reconstruction.
    anyhow::ensure!(
        account.to_commitment() == witness.state_commitment(),
        "the reconstructed account {account_id} does not match its witness at block {block_num}",
    );

    Ok((account, witness))
}
