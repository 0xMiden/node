use std::collections::BTreeSet;
use std::num::NonZeroU16;

use anyhow::Context;
use miden_node_proto::clients::RemoteProverClient;
use miden_node_proto::generated::remote_prover::ProofRequest;
use miden_node_proto::generated::remote_prover::proof::Proof;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::{BuildUnchecked, DecodeMessage};
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{
    Account,
    AccountId,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
};
use miden_protocol::asset::{AssetId, AssetWitness, FungibleAsset};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionInputs,
};
use miden_protocol::vm::{AdviceMap, FutureMaybeSend};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::note::TxFeeNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::auth::BasicAuthenticator;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};

pub(crate) struct CollectionContext {
    pub account: Account,
    pub block_header: BlockHeader,
    pub protocol_config: ProtocolConfig,
    pub blockchain: PartialBlockchain,
}

pub(super) async fn execute(
    context: CollectionContext,
    notes: Vec<Note>,
    keys: &[AuthSecretKey],
) -> anyhow::Result<ExecutedTransaction> {
    let fee_faucet = context.protocol_config.fee_asset_id().faucet_id();
    let serial_number = Word::from(rand::random::<[u32; 4]>());
    let (auth_args, advice) =
        commit_fee_conversion_info(FeeConversionInfo::one_to_one(fee_faucet), serial_number);
    let mut tx_args = TransactionArgs::new(AdviceMap::default()).with_auth_args(auth_args);
    tx_args.extend_advice_map([(auth_args, advice)]);

    let mut outputs = Vec::new();
    if context.block_header.fee_parameters().verification_base_fee() == 0 {
        // AuthSingleSig omits the fee note when the verification base fee is zero.
        let fee_note: Note = TxFeeNote::builder()
            .sender(context.account.id())
            .serial_number(serial_number)
            .asset(FungibleAsset::new(fee_faucet, 0)?)
            .build()?
            .into();
        tx_args.extend_advice_map(fee_note.recipient().to_advice_map_entries());
        outputs.push(fee_note.into());
    }
    let script = SendNotesTransactionScript::with_expiration_delta(
        &context.account.code_interface(),
        &outputs,
        NonZeroU16::new(super::EXPIRATION_BLOCKS).expect("expiration is nonzero"),
    )?;
    tx_args = tx_args.with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());
    let mast_store = TransactionMastStore::new();
    mast_store.load_account_code(context.account.code());
    let store = CollectionDataStore { context, mast_store };
    let authenticator = BasicAuthenticator::new(keys);
    // The RPC checks note existence. The batch proof authenticates the committed input notes.
    Ok(TransactionExecutor::new(&store)
        .with_authenticator(&authenticator)
        .execute_transaction(
            store.context.account.id(),
            store.context.block_header.block_num(),
            InputNotes::from_unauthenticated_notes(notes)?,
            tx_args,
        )
        .await?)
}

pub(super) async fn prove(
    prover: &RemoteProverClient,
    inputs: &TransactionInputs,
) -> anyhow::Result<ProvenTransaction> {
    let response = prover
        .clone()
        .prove(ProofRequest {
            request: Some(Request::Transaction(inputs.into())),
        })
        .await
        .context("failed to prove fee collection transaction")?
        .into_inner();
    let Some(Proof::Transaction(transaction)) = response.proof else {
        anyhow::bail!("remote prover response is missing a transaction proof");
    };
    transaction
        .decode_fields()?
        .build_unchecked()
        .context("failed to decode fee collection transaction proof")
}

struct CollectionDataStore {
    context: CollectionContext,
    mast_store: TransactionMastStore,
}

impl DataStore for CollectionDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            if account_id != self.context.account.id()
                || !ref_blocks.contains(&self.context.block_header.block_num())
            {
                return Err(DataStoreError::other("invalid fee collection transaction inputs"));
            }
            Ok((
                PartialAccount::from(&self.context.account),
                self.context.block_header.clone(),
                self.context.protocol_config.clone(),
                self.context.blockchain.clone(),
            ))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        _id: AccountId,
        _block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async { Err(DataStoreError::other("fee collection does not use foreign accounts")) }
    }

    fn get_vault_asset_witnesses(
        &self,
        id: AccountId,
        root: Word,
        assets: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            if id != self.context.account.id() || root != self.context.account.vault().root() {
                return Err(DataStoreError::other("invalid fee collection vault"));
            }
            Ok(assets
                .into_iter()
                .map(|asset| self.context.account.vault().open(asset))
                .collect())
        }
    }

    fn get_storage_map_witness(
        &self,
        _id: AccountId,
        _root: Word,
        _key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async { Err(DataStoreError::other("fee collection does not use storage maps")) }
    }

    fn get_note_script(
        &self,
        _root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async { Ok(None) }
    }
}

impl MastForestStore for CollectionDataStore {
    fn get(&self, hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(hash)
    }
}
