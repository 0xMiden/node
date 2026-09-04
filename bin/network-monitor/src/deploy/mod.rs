//! Account deployment module.
//!
//! This module contains functionality for deploying Miden accounts to the network.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use backon::{ExponentialBuilder, Retryable};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::account::{AccountResponse, AccountVaultDetails, StorageMapEntries};
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
    verify_transaction_encryption_key,
};
use miden_node_proto::generated::rpc::{
    AccountRequest as ProtoAccountRequest,
    BlockHeaderByNumberRequest,
    FinalityLevel,
    SyncChainMmrRequest,
};
use miden_node_proto::generated::transaction::ProvenTransaction as ProtoProvenTransaction;
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{debug, info, miden_instrument, warn};
use miden_node_utils::retry;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    PartialAccount,
    StorageMap,
    StorageMapKey,
    StorageMapWitness,
    StorageSlot,
    StorageSlotContent,
    StorageSlotType,
};
use miden_protocol::asset::{AssetId, AssetWitness};
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::crypto::dsa::falcon512_poseidon2::SecretKey;
use miden_protocol::crypto::merkle::mmr::{Forest, MmrDelta, MmrPeaks, PartialMmr};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteScript,
    NoteScriptRoot,
    NoteType,
    PartialNote,
    PartialNoteMetadata,
};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNote,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionInputs,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::vm::FutureMaybeSend;
use miden_standards::note::P2idNoteStorage;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};
use tokio::sync::Mutex;
use url::Url;

use crate::deploy::counter::create_counter_account;
use crate::deploy::wallet::create_wallet_account;
use crate::funding::{FaucetClient, FeeFunder, counter_funding_amount, wallet_funding_amount};
use crate::{COMPONENT, LOG_TARGET};

pub mod counter;
pub mod wallet;

/// Monitor accounts and signing key created as one deployment unit.
pub struct DeployedMonitorAccounts {
    pub wallet: Account,
    pub secret_key: SecretKey,
    pub counter: Account,
    pub counter_anchor: CounterAnchor,
    /// Faucet note funding the wallet's fees, consumed by its first increment transaction. `None`
    /// on zero-fee chains.
    pub wallet_funding_note: Option<Note>,
}

/// RPC client and verified transaction-input sealer shared by monitor submission workflows.
#[derive(Clone)]
pub struct TransactionSubmissionClient {
    rpc_client: RpcClient,
    genesis_commitment: Word,
    trusted_validator_signing_keys: Arc<[ValidatorPublicKey]>,
    sealer: Arc<Mutex<Option<TransactionInputsSealer>>>,
}

impl TransactionSubmissionClient {
    /// Connects to RPC and pins the validator key trusted for encryption-key attestations.
    pub async fn connect(
        rpc_url: &Url,
        timeout: Duration,
        trusted_validator_signing_key: ValidatorPublicKey,
    ) -> Result<Self> {
        let (rpc_client, genesis_commitment) =
            create_genesis_aware_rpc_client(rpc_url, timeout).await?;
        let client = Self {
            rpc_client,
            genesis_commitment,
            trusted_validator_signing_keys: Arc::from([trusted_validator_signing_key]),
            sealer: Arc::new(Mutex::new(None)),
        };
        client.sealer().await?;
        Ok(client)
    }

    /// Returns a clone of the underlying RPC client for read operations.
    pub fn rpc_client(&self) -> RpcClient {
        self.rpc_client.clone()
    }

    /// Returns the cached verified sealer, fetching and checking the attested key on first use.
    async fn sealer(&self) -> Result<TransactionInputsSealer> {
        if let Some(sealer) = self.sealer.lock().await.clone() {
            return Ok(sealer);
        }

        let key = self
            .rpc_client
            .clone()
            .get_transaction_encryption_key(())
            .await
            .context("Failed to fetch the transaction encryption key")?
            .into_inner();
        let verified = verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_signing_keys,
            ),
        )
        .context("Untrusted transaction encryption key")?;
        let sealer = TransactionInputsSealer::new(verified);

        let mut cached = self.sealer.lock().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }
        *cached = Some(sealer.clone());
        Ok(sealer)
    }

    /// Seals and submits one proven transaction, retrying once with a fresh key when needed.
    pub async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        transaction_inputs: &[u8],
    ) -> Result<BlockNumber> {
        let transaction = proven_tx.to_bytes();
        let tx_id = proven_tx.id();
        let stale_key = AtomicBool::new(false);

        let result = (|| {
            let transaction = transaction.clone();
            async {
                if stale_key.swap(false, Ordering::Relaxed) {
                    *self.sealer.lock().await = None;
                }

                let sealed = self
                    .sealer()
                    .await?
                    .seal(tx_id, transaction_inputs)
                    .context("Failed to seal the transaction inputs")?;
                self.rpc_client
                    .clone()
                    .submit_proven_tx(ProtoProvenTransaction {
                        transaction,
                        sealed_transaction_inputs: Some(sealed),
                    })
                    .await
                    .context("Failed to submit proven transaction to RPC")
            }
        })
        .retry(retry::constant(Duration::ZERO, Some(1)))
        .when(|err: &anyhow::Error| {
            err.downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::FailedPrecondition)
        })
        .notify(|status: &anyhow::Error, _| {
            stale_key.store(true, Ordering::Relaxed);
            warn!(
                status,
                target: COMPONENT,
                "Transaction inputs rejected as stale, refreshing the encryption key and retrying",
                transaction.id = tx_id
            );
        })
        .await;

        Ok(result?.into_inner().block_num.into())
    }
}

/// Backoff schedule applied to the genesis-discovery RPC handshake.
///
/// At startup the monitor may come up before the node's RPC endpoint is accepting connections, so
/// the eager `connect()` (and the follow-up `get_block_header_by_number` request) is retried with
/// exponential backoff instead of failing on the first refused connection. The schedule is bounded
/// so a single handshake attempt returns within a few minutes; callers that must survive a
/// genuinely unreachable endpoint (e.g. the NTX bootstrap in `monitor::tasks`) wrap it in their
/// own unbounded retry loop.
const GENESIS_DISCOVERY_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const GENESIS_DISCOVERY_BACKOFF_MAX: Duration = Duration::from_secs(30);
const GENESIS_DISCOVERY_MAX_RETRIES: usize = 10;

/// Builds the [`ExponentialBuilder`] used to back off retries on transient genesis-discovery
/// failures.
fn genesis_discovery_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(GENESIS_DISCOVERY_BACKOFF_INITIAL)
        .with_max_delay(GENESIS_DISCOVERY_BACKOFF_MAX)
        .with_factor(2.0)
        .with_max_times(GENESIS_DISCOVERY_MAX_RETRIES)
        .with_jitter()
}

/// Create an RPC client configured with the correct genesis metadata in the `Accept` header so that
/// write RPCs such as `SubmitProvenTx` are accepted by the node.
///
/// The full handshake (genesis discovery plus the genesis-aware reconnect) is retried with
/// [`genesis_discovery_backoff`] so a node that is still starting up does not abort the monitor.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<(RpcClient, Word)> {
    (|| async {
        // First, create a temporary client without genesis metadata to discover the genesis block
        // header and its commitment.
        let mut rpc: RpcClient = Builder::new(rpc_url.clone())
            .with_tls()
            .context("Failed to configure TLS for RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect()
            .await
            .context("Failed to create RPC client for genesis discovery")?;

        let block_header_request = BlockHeaderByNumberRequest {
            block_num: Some(BlockNumber::GENESIS.as_u32()),
            include_mmr_proof: None,
        };

        let response = rpc
            .get_block_header_by_number(block_header_request)
            .await
            .context("Failed to get genesis block header from RPC")?
            .into_inner();

        let genesis_block_header = response
            .block_header
            .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

        let genesis_header: BlockHeader =
            genesis_block_header.try_into().context("Failed to convert block header")?;
        let genesis_commitment = genesis_header.commitment();
        // Rebuild the client, this time including the required genesis metadata so that write RPCs
        // like SubmitProvenTx are accepted by the node.
        let rpc_client = Builder::new(rpc_url.clone())
            .with_tls()
            .context("Failed to configure TLS for RPC client")?
            .with_timeout(timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment)
            .without_otel_context_injection()
            .connect()
            .await
            .context("Failed to connect to RPC server with genesis metadata")?;

        Ok((rpc_client, genesis_commitment))
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

/// Create a fresh wallet + counter pair in memory and deploy the counter to the network.
///
/// Used both at startup and by the increment task when accounts are fundamentally outdated
/// (e.g., after a network reset) and re-syncing from the RPC is not sufficient. The accounts
/// are never persisted to disk; the monitor re-creates them on every restart.
pub async fn create_and_deploy_accounts(
    submission_client: &TransactionSubmissionClient,
    prover: &LocalTransactionProver,
    fee_faucet_id: AccountId,
    funding: Option<&FaucetClient>,
) -> Result<DeployedMonitorAccounts> {
    info!(target: LOG_TARGET, "Creating fresh monitor accounts");

    let mut rpc_client = submission_client.rpc_client();

    // The genesis header is immutable, so it is fetched once and reused by every step below.
    let genesis_header = fetch_genesis_block_header(&mut rpc_client).await?;
    let protocol_config = ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
        .context("failed to construct the target protocol configuration")?;
    ensure_anchor_protocol_config_matches(&genesis_header, &protocol_config)?;
    let mut funder = active_fee_funder(&genesis_header, funding, &rpc_client, fee_faucet_id)?;
    let verification_base_fee = genesis_header.fee_parameters().verification_base_fee();

    let (wallet_account, secret_key) = create_wallet_account()?;
    let counter_account =
        create_counter_account(wallet_account.id(), fee_faucet_id, verification_base_fee)?;

    // Both vaults start empty, so each account's first transaction pays its fee from a faucet note
    // consumed in that same transaction.
    let (counter_funding_note, wallet_funding_note) = match funder.as_mut() {
        Some(funder) => {
            let counter_note = funder
                .fund(counter_account.id(), counter_funding_amount(verification_base_fee))
                .await
                .context("failed to fund the counter account")?;
            let wallet_note = funder
                .fund(wallet_account.id(), wallet_funding_amount(verification_base_fee))
                .await
                .context("failed to fund the wallet account")?;
            (Some(counter_note), Some(wallet_note))
        },
        None => (None, None),
    };

    // The creation transaction anchors at the tip; on fee-charging chains the fee faucet is
    // provisioned as committed in that block (see `fetch_foreign_account_inputs`).
    let (tip_header, blockchain) =
        fetch_tip_chain_state(&mut rpc_client, genesis_header.commitment()).await?;
    ensure_anchor_protocol_config_matches(&tip_header, &protocol_config)?;
    let creation_fee_faucet = match funder.as_ref() {
        Some(_) => Some(
            fetch_foreign_account_inputs(&mut rpc_client, fee_faucet_id, tip_header.block_num())
                .await
                .context("failed to fetch the fee faucet's state at the reference block")?,
        ),
        None => None,
    };

    let committed_counter = Box::pin(deploy_counter_account(
        &counter_account,
        tip_header,
        protocol_config.clone(),
        blockchain,
        counter_funding_note,
        creation_fee_faucet,
        submission_client,
        prover,
    ))
    .await?;
    let anchored_fee_faucet_id = funder.is_some().then_some(fee_faucet_id);
    let counter_anchor = resolve_counter_anchor(
        &mut rpc_client,
        &genesis_header,
        &protocol_config,
        &committed_counter,
        anchored_fee_faucet_id,
    )
    .await?;

    info!(
        target: LOG_TARGET,
        "Successfully created and deployed accounts"
    );

    Ok(DeployedMonitorAccounts {
        wallet: wallet_account,
        secret_key,
        counter: counter_account,
        counter_anchor,
        wallet_funding_note,
    })
}

/// A fee-charging chain without a configured faucet. Permanent, so the NTX bootstrap aborts the
/// monitor instead of retrying (see `run_ntx`).
#[derive(Debug)]
pub struct UnsupportedChainError;

impl std::fmt::Display for UnsupportedChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "this chain charges transaction fees: configure --faucet-url so the monitor can fund \
             its accounts",
        )
    }
}

/// Returns the faucet client on fee-charging chains, `None` on zero-fee chains.
// TODO(#2450): Mainnet has no faucet service; it needs another funding path.
pub fn active_fee_funding<'a>(
    genesis_header: &BlockHeader,
    funding: Option<&'a FaucetClient>,
) -> Result<Option<&'a FaucetClient>> {
    if genesis_header.fee_parameters().verification_base_fee() == 0 {
        return Ok(None);
    }
    funding.map(Some).context(UnsupportedChainError)
}

/// Returns a [`FeeFunder`] on fee-charging chains, `None` on zero-fee chains.
///
/// The funder binds the faucet client to the given RPC client and to the fee faucet ID from the
/// genesis fee parameters.
pub fn active_fee_funder(
    genesis_header: &BlockHeader,
    funding: Option<&FaucetClient>,
    rpc_client: &RpcClient,
    fee_faucet_id: AccountId,
) -> Result<Option<FeeFunder>> {
    let funder = active_fee_funding(genesis_header, funding)?
        .map(|faucet| FeeFunder::new(faucet.clone(), rpc_client.clone(), fee_faucet_id));
    Ok(funder)
}

/// Fetches a public account in full (code, vault, storage with maps) plus its account-tree
/// witness at the given block.
///
/// Used to provision the fee faucet as a foreign account: the fee asset is callback-enabled, so
/// the kernel loads the issuing faucet whenever the asset enters or leaves a vault.
pub(crate) async fn fetch_foreign_account_inputs(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<(Account, AccountWitness)> {
    use miden_node_proto::generated::rpc::account_request::AccountDetailRequest;
    use miden_node_proto::generated::rpc::account_request::account_detail_request::StorageRequest;

    let id_bytes: [u8; 15] = account_id.into();
    // Dummy commitments force the server to include code and vault data in the response.
    let dummy: miden_node_proto::generated::primitives::Digest = Word::default().into();
    let request = ProtoAccountRequest {
        account_id: Some(miden_node_proto::generated::account::AccountId { id: id_bytes.to_vec() }),
        block_num: Some(block_num.into()),
        details: Some(AccountDetailRequest {
            code_commitment: Some(dummy),
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
        AccountResponse::try_from(response).context("failed to convert the account response")?;

    let witness = response.witness;
    anyhow::ensure!(
        witness.id() == account_id,
        "account tree returned a witness for {} when {account_id} was requested",
        witness.id(),
    );

    let details = response
        .details
        .with_context(|| format!("no details returned for public account {account_id}"))?;

    let code = AccountCode::read_from_bytes(
        &details.account_code.context("server did not return the account code")?,
    )
    .context("failed to deserialize the account code")?;

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
                    "storage map root for slot {} does not match the storage header",
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

    // Witness and details come from one response, so a mismatch means a bad reconstruction.
    anyhow::ensure!(
        account.to_commitment() == witness.state_commitment(),
        "reconstructed account {account_id} does not match its witness at block {block_num}",
    );

    Ok((account, witness))
}

/// The immutable chain state that counter-increment transactions are anchored at.
///
/// Every increment transaction emits a note targeted at the counter account, which makes the
/// paying account's auth procedure invoke the counter account's `estimate_note_fee` through FPI.
/// The kernel authenticates the foreign account against the reference block's account root, so the
/// transaction must reference a block that already contains the counter account, and the counter
/// state fed to the executor must be the state committed in that block.
///
/// The anchor is resolved once, right after deployment and before any increment note exists, and
/// then reused: the referenced block is historical and immutable, so later increments (which do
/// change the counter's live state) never invalidate it.
pub struct CounterAnchor {
    /// Header of the block the increment transactions reference.
    pub block_header: BlockHeader,
    /// Chain MMR whose peaks hash to `block_header.chain_commitment()`.
    pub blockchain: PartialBlockchain,
    /// Protocol configuration committed by `block_header`.
    pub protocol_config: ProtocolConfig,
    /// The counter account exactly as committed in `block_header`.
    pub counter_account: Account,
    /// Witness proving `counter_account`'s inclusion in `block_header`'s account tree.
    pub witness: AccountWitness,
    /// The fee faucet as committed in `block_header`, with its witness. Every transaction moving
    /// the callback-enabled fee asset loads the faucet, so increments need it. `None` on zero-fee
    /// chains.
    pub fee_faucet: Option<(Account, AccountWitness)>,
}

/// Number of attempts to resolve the counter anchor before giving up.
const ANCHOR_RESOLUTION_ATTEMPTS: usize = 30;

/// Delay between counter anchor resolution attempts.
const ANCHOR_RESOLUTION_DELAY: Duration = Duration::from_secs(1);

/// Resolve the [`CounterAnchor`] for a freshly deployed counter account.
///
/// Retries until the chain tip contains the counter account in the state `committed_counter`
/// describes, since the deployment transaction needs a block to land in first.
async fn resolve_counter_anchor(
    rpc_client: &mut RpcClient,
    genesis_header: &BlockHeader,
    protocol_config: &ProtocolConfig,
    committed_counter: &Account,
    fee_faucet_id: Option<AccountId>,
) -> Result<CounterAnchor> {
    let genesis_commitment = genesis_header.commitment();
    let expected_state = committed_counter.to_commitment();
    let mut last_error = None;

    for attempt in 1..=ANCHOR_RESOLUTION_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(ANCHOR_RESOLUTION_DELAY).await;
        }

        match try_resolve_counter_anchor(
            rpc_client,
            committed_counter,
            expected_state,
            genesis_commitment,
            protocol_config,
            fee_faucet_id,
        )
        .await
        {
            Ok(Some(anchor)) => {
                info!(
                    target: LOG_TARGET,
                    "Resolved counter FPI anchor",
                    account.id = committed_counter.id(),
                    block.number = anchor.block_header.block_num()
                );
                return Ok(anchor);
            },
            Ok(None) => debug!(
                target: LOG_TARGET,
                "Counter account not yet committed in the expected state; retrying",
                account.id = committed_counter.id(),
                retry.attempt = attempt
            ),
            Err(err) => {
                debug!(
                    &err,
                    target: LOG_TARGET,
                    "Counter anchor resolution attempt failed; retrying",
                    account.id = committed_counter.id(),
                    retry.attempt = attempt
                );
                last_error = Some(err);
            },
        }
    }

    let reason = last_error.map_or_else(
        || "the account was never committed in the expected state".to_string(),
        |err| format!("{err:#}"),
    );
    anyhow::bail!(
        "could not resolve the FPI anchor for counter account {} within {} attempts: {reason}",
        committed_counter.id(),
        ANCHOR_RESOLUTION_ATTEMPTS
    )
}

/// One [`resolve_counter_anchor`] attempt.
///
/// Returns `Ok(None)` when the chain is reachable but does not yet hold the counter account in the
/// expected state, which is the normal case while the deployment transaction is still in flight.
async fn try_resolve_counter_anchor(
    rpc_client: &mut RpcClient,
    committed_counter: &Account,
    expected_state: Word,
    genesis_commitment: Word,
    protocol_config: &ProtocolConfig,
    fee_faucet_id: Option<AccountId>,
) -> Result<Option<CounterAnchor>> {
    let (block_header, blockchain) = fetch_tip_chain_state(rpc_client, genesis_commitment).await?;
    ensure_anchor_protocol_config_matches(&block_header, protocol_config)?;
    let block_num = block_header.block_num();

    let witness = fetch_account_witness(rpc_client, committed_counter.id(), block_num).await?;

    // An account absent from the tree yields a witness for the requested ID whose commitment is the
    // empty word, so a plain state comparison covers "not committed yet" as well. Pin the ID too:
    // an account-ID prefix collision makes the tree return a witness for the *other* account, and
    // `MonitorDataStore` keys witnesses by the account they prove.
    if witness.id() != committed_counter.id() {
        anyhow::bail!(
            "account tree returned a witness for {} when {} was requested",
            witness.id(),
            committed_counter.id()
        );
    }

    if witness.state_commitment() != expected_state {
        return Ok(None);
    }

    // The kernel authenticates the faucet against the anchor block's account root, so fetch it
    // exactly as committed there.
    let fee_faucet = match fee_faucet_id {
        Some(faucet_id) => {
            Some(fetch_foreign_account_inputs(rpc_client, faucet_id, block_num).await?)
        },
        None => None,
    };

    Ok(Some(CounterAnchor {
        block_header,
        blockchain,
        protocol_config: protocol_config.clone(),
        counter_account: committed_counter.clone(),
        witness,
        fee_faucet,
    }))
}

/// Ensures that a transaction anchor and its protocol configuration describe the same state.
fn ensure_anchor_protocol_config_matches(
    block_header: &BlockHeader,
    protocol_config: &ProtocolConfig,
) -> Result<()> {
    let provided_commitment = protocol_config.to_commitment();
    let expected_commitment = block_header.protocol_config_commitment();
    anyhow::ensure!(
        provided_commitment == expected_commitment,
        "protocol configuration commitment {provided_commitment} does not match anchor block {} \
         commitment {expected_commitment}",
        block_header.block_num(),
    );
    Ok(())
}

/// Fetch the chain tip header together with a [`PartialBlockchain`] whose peaks hash to that
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
        .context("sync_chain_mmr response did not include a block header")?
        .try_into()
        .context("failed to convert the sync target block header")?;

    let delta: MmrDelta = response
        .mmr_delta
        .context("sync_chain_mmr response did not include an MMR delta")?
        .try_into()
        .context("failed to convert the MMR delta")?;

    let mut mmr = PartialMmr::from_peaks(
        MmrPeaks::new(Forest::new(0).context("empty forest should be valid")?, Vec::new())
            .context("empty MMR peaks should be valid")?,
    );

    if tip_header.block_num() != BlockNumber::GENESIS {
        mmr.add(genesis_commitment, false)
            .context("failed to seed the MMR with the genesis block")?;
        mmr.apply(delta).context("failed to apply the MMR delta")?;
    }

    anyhow::ensure!(
        mmr.peaks().hash_peaks() == tip_header.chain_commitment(),
        "synced MMR peaks do not match the chain commitment of block {}",
        tip_header.block_num()
    );

    let blockchain = PartialBlockchain::new(mmr, Vec::new())
        .context("failed to build the partial blockchain")?;

    Ok((tip_header, blockchain))
}

/// Fetch the account-tree witness proving an account's state in the given block.
async fn fetch_account_witness(
    rpc_client: &mut RpcClient,
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<AccountWitness> {
    let request = ProtoAccountRequest {
        account_id: Some(account_id.into()),
        block_num: Some(block_num.into()),
        details: None,
    };

    let response = rpc_client
        .get_account(request)
        .await
        .context("failed to fetch the account witness")?
        .into_inner();

    let response =
        AccountResponse::try_from(response).context("failed to convert the account response")?;

    Ok(response.witness)
}

/// Fetch the genesis block header from RPC.
async fn fetch_genesis_block_header(rpc_client: &mut RpcClient) -> Result<BlockHeader> {
    let block_header_request = BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    };

    let response = rpc_client
        .get_block_header_by_number(block_header_request)
        .await
        .context("Failed to get the genesis block header from RPC")?;

    let root_block_header = response
        .into_inner()
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    root_block_header.try_into().context("Failed to convert block header")
}

/// Execute the counter account's genesis (creation) transaction in-memory.
///
/// Builds a [`MonitorDataStore`] over the given reference block and executes the creation
/// transaction. Does not prove or submit.
///
/// On a fee-charging chain the transaction consumes `funding_note` to pay its fee: a new
/// account's vault is empty at the prologue, and the fee is withdrawn in the epilogue, after the
/// note's assets land. The note is consumed unauthenticated; the node authenticates it at
/// submission.
pub(crate) async fn execute_counter_genesis_tx(
    counter_account: &Account,
    reference_header: BlockHeader,
    protocol_config: ProtocolConfig,
    blockchain: PartialBlockchain,
    funding_note: Option<Note>,
    fee_faucet: Option<(Account, AccountWitness)>,
) -> Result<ExecutedTransaction> {
    let reference_block = reference_header.block_num();
    let mut data_store = MonitorDataStore::new(reference_header, protocol_config, blockchain);
    data_store.add_account(counter_account.clone());
    // Paying the fee moves the callback-enabled asset, which loads the issuing faucet.
    if let Some((faucet_account, faucet_witness)) = fee_faucet {
        data_store.add_foreign_account(faucet_account, faucet_witness);
    }

    let executor: TransactionExecutor<'_, '_, _, BasicAuthenticator> =
        TransactionExecutor::new(&data_store);

    // Protocol 0.17 requires every network-account transaction to have an effect before fee
    // payment. A funding note supplies this effect on fee-charging chains. Emit an empty private
    // note when the chain has no fees so that account creation also satisfies this rule.
    let tx_args = match funding_note.as_ref() {
        Some(_) => TransactionArgs::default(),
        None => counter_creation_tx_args(counter_account)?,
    };

    let input_notes = match funding_note {
        Some(note) => InputNotes::new(vec![InputNote::unauthenticated(note)])
            .context("failed to build the creation transaction's input notes")?,
        None => InputNotes::default(),
    };

    let executed_tx = executor
        .execute_transaction(counter_account.id(), reference_block, input_notes, tx_args)
        .await
        .context("Failed to execute transaction")?;

    Ok(executed_tx)
}

fn counter_creation_tx_args(counter_account: &Account) -> Result<TransactionArgs> {
    let recipient = P2idNoteStorage::new(counter_account.id()).into_recipient(Word::default());
    let note = Note::new(
        NoteAssets::default(),
        PartialNoteMetadata::new(counter_account.id(), NoteType::Private),
        recipient.clone(),
    );
    let partial_note = PartialNote::from(note);
    let script = SendNotesTransactionScript::new(
        &counter_account.code_interface(),
        std::slice::from_ref(&partial_note),
    )
    .context("failed to build the counter creation transaction script")?;

    let mut tx_args = TransactionArgs::default()
        .with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());
    tx_args.add_output_note_recipient(Box::new(recipient));
    Ok(tx_args)
}

/// Build a valid set of transaction inputs for a throwaway counter genesis transaction.
///
/// Used as the static payload for the remote-prover probe: it produces a real, self-consistent
/// transaction the remote prover can re-execute and prove, without depending on the network
/// transaction service or any pre-existing on-chain account. The only network access is the RPC
/// handshake plus a single read of the genesis block header, which supplies both the reference block
/// and the fee faucet the counter's fee policy is denominated in. Nothing is proven or submitted
/// here.
///
/// On a fee-charging chain a faucet note is claimed and consumed to pay the fee. The transaction
/// is never submitted, so the note is never spent on-chain: one claim serves every probe run.
pub async fn build_probe_transaction_inputs(
    rpc_url: &Url,
    fee_faucet_id: AccountId,
    funding: Option<&FaucetClient>,
) -> Result<TransactionInputs> {
    let (wallet_account, _secret_key) = create_wallet_account()?;

    let (mut rpc_client, _) =
        create_genesis_aware_rpc_client(rpc_url, Duration::from_secs(10)).await?;
    let genesis_header = fetch_genesis_block_header(&mut rpc_client).await?;
    let protocol_config = ProtocolConfig::current(AssetId::new_fungible(fee_faucet_id))
        .context("failed to construct the target protocol configuration")?;
    ensure_anchor_protocol_config_matches(&genesis_header, &protocol_config)?;
    let mut funder = active_fee_funder(&genesis_header, funding, &rpc_client, fee_faucet_id)?;
    let verification_base_fee = genesis_header.fee_parameters().verification_base_fee();
    let counter_account =
        create_counter_account(wallet_account.id(), fee_faucet_id, verification_base_fee)?;

    let (tip_header, blockchain) =
        fetch_tip_chain_state(&mut rpc_client, genesis_header.commitment()).await?;
    ensure_anchor_protocol_config_matches(&tip_header, &protocol_config)?;
    let (funding_note, fee_faucet) = match funder.as_mut() {
        Some(funder) => {
            let note = funder
                .fund(counter_account.id(), counter_funding_amount(verification_base_fee))
                .await
                .context("failed to fund the probe's counter account")?;
            let faucet = fetch_foreign_account_inputs(
                &mut rpc_client,
                fee_faucet_id,
                tip_header.block_num(),
            )
            .await
            .context("failed to fetch the fee faucet's state at the reference block")?;
            (Some(note), Some(faucet))
        },
        None => (None, None),
    };

    let executed_tx = execute_counter_genesis_tx(
        &counter_account,
        tip_header,
        protocol_config,
        blockchain,
        funding_note,
        fee_faucet,
    )
    .await?;

    Ok(executed_tx.tx_inputs().clone())
}

/// Deploy a counter account to the network by submitting its genesis transaction via RPC.
#[expect(
    clippy::too_many_arguments,
    reason = "the arguments describe the account, its complete transaction anchor, and submission"
)]
#[miden_instrument(
    target = COMPONENT,
    name = "deploy-counter-account",
    ret(level = "debug"),
)]
pub async fn deploy_counter_account(
    counter_account: &Account,
    reference_header: BlockHeader,
    protocol_config: ProtocolConfig,
    blockchain: PartialBlockchain,
    funding_note: Option<Note>,
    fee_faucet: Option<(Account, AccountWitness)>,
    submission_client: &TransactionSubmissionClient,
    prover: &LocalTransactionProver,
) -> Result<Account> {
    let executed_tx = execute_counter_genesis_tx(
        counter_account,
        reference_header,
        protocol_config,
        blockchain,
        funding_note,
        fee_faucet,
    )
    .await?;

    let transaction_inputs = executed_tx.tx_inputs().to_bytes();

    let committed_counter = Account::try_from(executed_tx.account_patch())
        .context("counter creation patch should convert to an account")?;

    let prover = prover.clone();
    let proven_tx = spawn_blocking_in_current_span(move || prover.prove(executed_tx))
        .await
        .context("prover task panicked")?
        .context("Failed to prove transaction")?;

    submission_client.submit(&proven_tx, &transaction_inputs).await?;

    Ok(committed_counter)
}

// MONITOR DATA STORE
// ================================================================================================

/// A [`DataStore`] implementation for the network monitor.
pub struct MonitorDataStore {
    accounts: HashMap<AccountId, Account>,
    account_witnesses: HashMap<AccountId, AccountWitness>,
    block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_block_chain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl MonitorDataStore {
    pub fn new(
        block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_block_chain: PartialBlockchain,
    ) -> Self {
        Self {
            accounts: HashMap::new(),
            account_witnesses: HashMap::new(),
            block_header,
            protocol_config,
            partial_block_chain,
            mast_store: TransactionMastStore::new(),
        }
    }

    /// Add or replace an account in the store and load its code into the MAST store.
    pub fn add_account(&mut self, account: Account) {
        self.mast_store.load_account_code(account.code());
        self.accounts.insert(account.id(), account);
    }

    /// Register an account the transaction reaches through a foreign procedure invocation, together
    /// with the account-tree witness proving its state in the store's reference block.
    pub fn add_foreign_account(&mut self, account: Account, witness: AccountWitness) {
        self.add_account(account);
        self.account_witnesses.insert(witness.id(), witness);
    }

    /// Returns a reference to the account or a standardized "unknown account" error.
    fn get_account(&self, account_id: AccountId) -> Result<&Account, DataStoreError> {
        self.accounts.get(&account_id).ok_or_else(|| DataStoreError::Other {
            error_msg: "unknown account".into(),
            source: None,
        })
    }
}

impl DataStore for MonitorDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        mut _block_refs: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            ensure_anchor_protocol_config_matches(&self.block_header, &self.protocol_config)
                .map_err(|err| DataStoreError::Other {
                    error_msg: err.to_string().into(),
                    source: None,
                })?;
            let account = self.get_account(account_id)?;
            let partial_account = PartialAccount::from(account);

            Ok((
                partial_account,
                self.block_header.clone(),
                self.protocol_config.clone(),
                self.partial_block_chain.clone(),
            ))
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            let account = self.get_account(account_id)?;

            account
                .storage()
                .slots()
                .iter()
                .filter_map(|slot| match slot.content() {
                    StorageSlotContent::Map(map) => Some(map),
                    StorageSlotContent::Value(_) => None,
                })
                .find(|map| map.root() == map_root)
                .map(|map| map.open(&map_key))
                .ok_or_else(|| DataStoreError::Other {
                    error_msg: format!(
                        "no storage map with the requested root in account {account_id}"
                    )
                    .into(),
                    source: None,
                })
        }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            let account = self.get_account(foreign_account_id)?;
            let witness =
                self.account_witnesses.get(&foreign_account_id).cloned().ok_or_else(|| {
                    DataStoreError::Other {
                        error_msg: format!(
                            "no account witness for foreign account {foreign_account_id}"
                        )
                        .into(),
                        source: None,
                    }
                })?;

            Ok(AccountInputs::new(PartialAccount::from(account), witness))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        vault_keys: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            let account = self.get_account(account_id)?;

            if account.vault().root() != vault_root {
                return Err(DataStoreError::Other {
                    error_msg: "vault root mismatch".into(),
                    source: None,
                });
            }

            vault_keys
                .into_iter()
                .map(|vault_key| {
                    AssetWitness::new(account.vault().open(vault_key).into(), [vault_key]).map_err(
                        |err| DataStoreError::Other {
                            error_msg: "failed to open vault asset tree".into(),
                            source: Some(Box::new(err)),
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        }
    }

    fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async move { Ok(None) }
    }
}

impl MastForestStore for MonitorDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use miden_protocol::asset::{AssetId, FungibleAsset};
    use miden_protocol::crypto::merkle::mmr::{MmrPeaks, PartialMmr};
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::transaction::PartialBlockchain;
    use miden_testing::MockChain;

    use super::{DataStore, FaucetClient, MonitorDataStore, active_fee_funding};
    use crate::deploy::wallet::create_wallet_account;

    /// A fee-charging chain without a faucet must fail at startup; a zero-fee chain must not fund
    /// even when a faucet is configured.
    #[test]
    fn fee_funding_is_required_exactly_on_fee_charging_chains() {
        let funding = FaucetClient::new(
            url::Url::parse("http://faucet.invalid").expect("static URL is valid"),
            Duration::from_secs(1),
        );

        let zero_fee_chain = MockChain::builder().build().expect("chain should build");
        let active = active_fee_funding(&zero_fee_chain.genesis_block_header(), Some(&funding))
            .expect("a zero base fee needs no funding");
        assert!(active.is_none(), "no funding must happen on a zero-fee chain");

        let fee_charging_chain = MockChain::builder()
            .verification_base_fee(500)
            .build()
            .expect("chain should build");
        let genesis_header = fee_charging_chain.genesis_block_header();

        let active = active_fee_funding(&genesis_header, Some(&funding))
            .expect("a fee-charging chain with a faucet is supported");
        assert!(active.is_some(), "funding must be active on a fee-charging chain");

        let err = active_fee_funding(&genesis_header, None)
            .expect_err("a fee-charging chain without a faucet must be rejected");
        assert!(
            format!("{err:#}").contains("--faucet-url"),
            "the error should point at the missing configuration, got: {err:#}"
        );
        // The bootstrap retry loop keys on this downcast to abort instead of retrying.
        assert!(
            err.downcast_ref::<super::UnsupportedChainError>().is_some(),
            "the missing-faucet error must be typed as permanent"
        );
    }

    #[tokio::test]
    async fn data_store_rejects_a_protocol_config_mismatched_with_its_anchor_header() {
        let chain = MockChain::builder().build().expect("chain should build");
        let mismatched_fee_faucet = FungibleAsset::mock_issuer();
        assert_ne!(mismatched_fee_faucet, chain.fee_faucet_id());
        let mismatched_protocol_config =
            ProtocolConfig::current(AssetId::new_fungible(mismatched_fee_faucet))
                .expect("protocol config should build");
        let anchor_header = chain.genesis_block_header();
        assert_ne!(
            mismatched_protocol_config.to_commitment(),
            anchor_header.protocol_config_commitment(),
        );

        let blockchain =
            PartialBlockchain::new(PartialMmr::from_peaks(MmrPeaks::default()), Vec::new())
                .expect("empty genesis blockchain should build");
        let (account, _) = create_wallet_account().expect("wallet should build");
        let mut data_store =
            MonitorDataStore::new(anchor_header, mismatched_protocol_config, blockchain);
        data_store.add_account(account.clone());

        let error = data_store
            .get_transaction_inputs(account.id(), BTreeSet::new())
            .await
            .expect_err("an inconsistent header/config pair must not be served");
        assert!(error.to_string().contains("protocol configuration commitment"));
    }
}
