//! RPC plumbing for submitting increment transactions.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
};
use miden_node_proto::domain::protocol_config::ensure_protocol_config_is_present_and_matches_header;
use miden_node_proto::generated::account::account_storage_header::storage_slot::Content as SlotContent;
use miden_node_proto::generated::rpc::account_request::AccountDetailRequest;
use miden_node_proto::generated::rpc::{
    AccountRequest,
    BlockHeaderByNumberRequest,
    BlockHeaderByNumberResponse,
};
use miden_node_proto::generated::submission::ProvenTransactionSubmission as ProtoProvenTransaction;
use miden_node_proto::{BuildUnchecked, DecodeMessage, DecodeMessageExt, VerifyWith};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::utils::serde::Deserializable;
use tokio::sync::Mutex;
use url::Url;

/// An RPC client that can submit transactions, plus the genesis header everything is anchored to.
pub struct SubmissionClient {
    rpc: RpcClient,
    genesis_header: BlockHeader,
    genesis_protocol_config: ProtocolConfig,
    genesis_commitment: Word,
    trusted_validator_keys: Arc<[ValidatorPublicKey]>,
    sealer: Mutex<Option<TransactionInputsSealer>>,
}

impl SubmissionClient {
    /// Connects to `rpc_url`, discovers the genesis block, and pins the validator key that
    /// attestations must be signed by.
    pub async fn connect(
        rpc_url: &Url,
        timeout: Duration,
        validator_signing_public_keys: &[String],
    ) -> Result<Self> {
        anyhow::ensure!(
            !validator_signing_public_keys.is_empty(),
            "at least one validator signing public key is required",
        );

        let trusted_keys = validator_signing_public_keys
            .iter()
            .map(|encoded| {
                let bytes = hex::decode(encoded).with_context(|| {
                    format!("validator signing public key {encoded} is not hex")
                })?;
                ValidatorPublicKey::read_from_bytes(&bytes).with_context(|| {
                    format!("validator signing public key {encoded} is not a valid K256 key")
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Step one: a client with no genesis metadata, used only to learn the genesis header. TLS
        // follows the URL scheme, so a local `http://` stack needs no extra flags. The builder is a
        // typestate, so the scheme branch is inlined rather than factored into a helper.
        let discovery = Builder::new(rpc_url.clone());
        let discovery = if rpc_url.scheme() == "https" {
            discovery.with_tls().context("failed to configure TLS for the RPC client")?
        } else {
            discovery.without_tls()
        };
        let mut discovery: RpcClient = discovery
            .with_timeout(timeout)
            .without_metadata_version()
            .without_metadata_genesis()
            .without_otel_context_injection()
            .connect()
            .await
            .context("failed to connect to RPC for genesis discovery")?;

        let (genesis_header, genesis_protocol_config) = genesis_block_state(&mut discovery).await?;
        let genesis_commitment = genesis_header.commitment();

        // Step two: the real client, carrying the genesis commitment so writes are accepted.
        let genesis_aware = Builder::new(rpc_url.clone());
        let genesis_aware = if rpc_url.scheme() == "https" {
            genesis_aware.with_tls().context("failed to configure TLS for the RPC client")?
        } else {
            genesis_aware.without_tls()
        };
        let rpc: RpcClient = genesis_aware
            .with_timeout(timeout)
            .without_metadata_version()
            .with_metadata_genesis(genesis_commitment)
            .without_otel_context_injection()
            .connect()
            .await
            .context("failed to connect to RPC")?;

        let client = Self {
            rpc,
            genesis_header,
            genesis_protocol_config,
            genesis_commitment,
            trusted_validator_keys: Arc::from(trusted_keys),
            sealer: Mutex::new(None),
        };

        // Fetch and verify the encryption key up front, so a bad validator key fails at startup
        // rather than on the first submission.
        client.sealer().await?;

        Ok(client)
    }

    /// The genesis block header, used as the reference block for every increment transaction.
    pub fn genesis_header(&self) -> &BlockHeader {
        &self.genesis_header
    }

    /// Returns the configuration committed by the genesis header.
    pub fn genesis_protocol_config(&self) -> &ProtocolConfig {
        &self.genesis_protocol_config
    }

    /// Reads the current chain tip height.
    ///
    /// Prefers the block producer's view when the node exposes one, since that is the height blocks
    /// are actually being produced at; otherwise falls back to the node's own tip.
    pub async fn chain_tip(&self) -> Result<u32> {
        let status = self
            .rpc
            .clone()
            .status(())
            .await
            .context("failed to read node status")?
            .into_inner();

        Ok(status.block_producer.map_or(status.chain_tip, |producer| producer.chain_tip))
    }

    /// Reads the `u64` held in the named value slot of an account, or `None` if the account is not
    /// on-chain yet.
    ///
    /// This is how the harness observes progress on the *other* side: the wallet's slot counts what
    /// this tool submitted, while the counter account's slot only advances when the ntx-builder has
    /// actually loaded the large account and consumed a network note.
    pub async fn slot_value(&self, account_id: AccountId, slot_name: &str) -> Result<Option<u64>> {
        let request = AccountRequest {
            account_id: Some(account_id.into()),
            block_num: None,
            details: Some(AccountDetailRequest {
                code_commitment: None,
                asset_vault_commitment: None,
                storage_request: None,
            }),
        };

        let response = self
            .rpc
            .clone()
            .get_account(request)
            .await
            .context("failed to read the account from RPC")?
            .into_inner();

        let Some(details) = response.details else {
            return Ok(None);
        };
        let storage_header = details
            .storage_details
            .context("RPC returned no storage details")?
            .header
            .context("RPC returned no storage header")?;

        let slot = storage_header
            .slots
            .iter()
            .find(|slot| slot.slot_name == slot_name)
            .with_context(|| format!("account has no storage slot named '{slot_name}'"))?;

        let value: Word = match slot.content.as_ref() {
            Some(SlotContent::Value(value)) => {
                value.try_into().context("failed to decode the storage slot value")?
            },
            Some(SlotContent::MapRoot(_)) => {
                anyhow::bail!("storage slot '{slot_name}' is a storage map")
            },
            None => anyhow::bail!("storage slot carries no value"),
        };

        // A value slot holds the number in the word's first element.
        Ok(Some(
            value
                .as_elements()
                .first()
                .expect("a word has four elements")
                .as_canonical_u64(),
        ))
    }

    /// Fetches the account-tree witness proving `account_id`'s state in `block_num`.
    ///
    /// Every increment emits a note targeted at the counter, which makes the wallet's auth procedure
    /// invoke the counter's `estimate_note_fee` through FPI. The kernel authenticates that foreign
    /// account against the reference block's account root, so the executor needs this witness.
    pub async fn account_witness(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
    ) -> Result<AccountWitness> {
        let request = AccountRequest {
            account_id: Some(account_id.into()),
            block_num: Some(block_num.into()),
            details: None,
        };

        let response = self
            .rpc
            .clone()
            .get_account(request)
            .await
            .context("failed to fetch the account witness from RPC")?
            .into_inner();

        let response =
            response.decode_and_verify().context("failed to decode the account response")?;

        // An account-ID prefix collision makes the tree return a witness for the *other* account,
        // and the data store keys witnesses by the account they prove.
        anyhow::ensure!(
            response.witness.id() == account_id,
            "account tree returned a witness for {} when {account_id} was requested",
            response.witness.id(),
        );

        Ok(response.witness)
    }

    /// Returns the cached sealer, fetching and verifying the attested encryption key on first use.
    async fn sealer(&self) -> Result<TransactionInputsSealer> {
        let mut cached = self.sealer.lock().await;
        if let Some(sealer) = cached.clone() {
            return Ok(sealer);
        }

        let key = self
            .rpc
            .clone()
            .get_transaction_encryption_key(())
            .await
            .context("failed to fetch the transaction encryption key")?
            .into_inner();

        let verified = key
            .verify_with(TrustedTransactionEncryptionState::new(
                self.genesis_commitment,
                &self.trusted_validator_keys,
            ))
            .context(
                "the node's transaction encryption key is not attested by the trusted validator",
            )?;

        let sealer = TransactionInputsSealer::new(verified);
        *cached = Some(sealer.clone());
        Ok(sealer)
    }

    /// Seals the transaction inputs and submits the proven transaction, returning the block height
    /// the node accepted it at.
    ///
    /// A rejection with `FailedPrecondition` means the encryption key rotated under us, so the cached
    /// sealer is dropped and the submission retried once against a freshly fetched key.
    pub async fn submit(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &[u8],
    ) -> Result<BlockNumber> {
        match self.try_submit(proven_tx, tx_inputs).await {
            Err(err) if is_stale_key(&err) => {
                *self.sealer.lock().await = None;
                self.try_submit(proven_tx, tx_inputs)
                    .await
                    .context("submission failed again after refreshing the encryption key")
            },
            other => other,
        }
    }

    async fn try_submit(
        &self,
        proven_tx: &ProvenTransaction,
        tx_inputs: &[u8],
    ) -> Result<BlockNumber> {
        let sealed = self
            .sealer()
            .await?
            .seal(proven_tx.id(), tx_inputs)
            .context("failed to seal the transaction inputs")?;

        let response = self
            .rpc
            .clone()
            .submit_proven_tx(ProtoProvenTransaction {
                transaction: Some(proven_tx.into()),
                sealed_transaction_inputs: Some(sealed),
            })
            .await
            .context("failed to submit the proven transaction")?;

        Ok(response.into_inner().block_num.into())
    }
}

/// Reads the genesis block header, which anchors both the client metadata and transaction
/// execution.
async fn genesis_block_state(rpc: &mut RpcClient) -> Result<(BlockHeader, ProtocolConfig)> {
    let response = rpc
        .get_block_header_by_number(genesis_header_request())
        .await
        .context("failed to read the genesis block header")?
        .into_inner();

    decode_genesis_block_state(response)
}

fn decode_genesis_block_state(
    response: BlockHeaderByNumberResponse,
) -> Result<(BlockHeader, ProtocolConfig)> {
    let header = response
        .block_header
        .context("RPC returned no genesis block header")?
        .decode_fields()
        .context("failed to decode the genesis block header")?
        // SAFETY: Genesis has no parent. This benchmark trusts the configured RPC for genesis.
        .build_unchecked()
        .context("failed to build the genesis block header")?;
    let protocol_config =
        ensure_protocol_config_is_present_and_matches_header(response.protocol_config, &header)
            .context("RPC returned no valid genesis protocol configuration")?;

    Ok((header, protocol_config))
}

fn genesis_header_request() -> BlockHeaderByNumberRequest {
    BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
        include_protocol_config: Some(true),
    }
}

/// True when the node rejected a submission because our sealed inputs used a stale encryption key.
fn is_stale_key(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| status.code() == tonic::Code::FailedPrecondition)
    })
}

#[cfg(test)]
mod tests {
    use miden_node_proto::generated::rpc::BlockHeaderByNumberResponse;
    use miden_protocol::account::AccountId;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
    use miden_testing::MockChain;

    use super::decode_genesis_block_state;

    #[test]
    fn genesis_response_rejects_mismatched_protocol_config() {
        let chain = MockChain::builder().build().expect("chain should build");
        let other = MockChain::builder()
            .fee_faucet_id(
                AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)
                    .expect("test faucet ID is valid"),
            )
            .build()
            .expect("chain should build");
        let response = BlockHeaderByNumberResponse {
            block_header: Some(chain.genesis_block_header().into()),
            mmr_path: None,
            chain_length: None,
            protocol_config: Some(other.protocol_config().into()),
        };

        let error = decode_genesis_block_state(response)
            .expect_err("the genesis configuration must match its header");

        assert!(format!("{error:#}").contains("does not match header commitment"));
    }
}
