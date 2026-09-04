use std::collections::BTreeSet;

use miden_node_store::genesis::pass_through::{
    build_pass_through_account,
    pass_through_sweep_component_code,
};
use miden_protocol::account::{
    Account,
    AccountId,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
};
use miden_protocol::asset::{Asset, AssetId, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteAssets, NoteScript, NoteScriptRoot, NoteTag, NoteType};
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
    TransactionScript,
};
use miden_protocol::vm::{AdviceMap, FutureMaybeSend};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNoteStorage;
use miden_tx::{
    DataStore,
    DataStoreError,
    LoadedMastForest,
    LocalTransactionProver,
    MastForestStore,
    TransactionExecutor,
    TransactionMastStore,
};

const PASS_THROUGH_TRANSACTION_SCRIPT: &str = include_str!("pass_through.masm");

/// Builds the transaction that converts a batch's fee notes into one P2ID note.
#[derive(Clone)]
pub(super) struct PassThroughTransactionBuilder {
    account: Account,
    target: AccountId,
    script: TransactionScript,
}

impl PassThroughTransactionBuilder {
    pub(super) fn new(target: AccountId) -> anyhow::Result<Self> {
        let account = build_pass_through_account()?;
        let sweep_component = pass_through_sweep_component_code()?;
        let script = CodeBuilder::default()
            .with_dynamically_linked_package(sweep_component)?
            .compile_tx_script(PASS_THROUGH_TRANSACTION_SCRIPT)?;

        Ok(Self { account, target, script })
    }

    pub(super) async fn execute(
        &self,
        notes: Vec<Note>,
        serial_number: Word,
        reference_block_header: BlockHeader,
        partial_blockchain: PartialBlockchain,
    ) -> anyhow::Result<ExecutedTransaction> {
        let asset_ids = notes
            .iter()
            .flat_map(|note| note.assets().iter())
            .map(Asset::id)
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            asset_ids.len() <= NoteAssets::MAX_NUM_ASSETS,
            "pass-through transaction names {} assets but at most {} fit into one note",
            asset_ids.len(),
            NoteAssets::MAX_NUM_ASSETS,
        );

        let (script, script_args) = self.script_and_args(serial_number, asset_ids);
        let mut tx_args =
            TransactionArgs::new(AdviceMap::default()).with_tx_script_and_args(script, script_args);
        let output_note_recipient = P2idNoteStorage::new(self.target).into_recipient(serial_number);
        tx_args.extend_advice_map(output_note_recipient.to_advice_map_entries());
        let notes = InputNotes::from_unauthenticated_notes(notes)?;
        let data_store = PassThroughDataStore::new(
            self.account.clone(),
            reference_block_header,
            partial_blockchain,
        );

        Ok(TransactionExecutor::<_, ()>::new(&data_store)
            .execute_transaction(
                self.account.id(),
                data_store.reference_block_header.block_num(),
                notes,
                tx_args,
            )
            .await?)
    }

    pub(super) fn prove(transaction: ExecutedTransaction) -> anyhow::Result<ProvenTransaction> {
        Ok(LocalTransactionProver::default().prove(transaction)?)
    }

    fn script_and_args(
        &self,
        serial_number: Word,
        asset_ids: impl IntoIterator<Item = AssetId>,
    ) -> (TransactionScript, Word) {
        let note_type = NoteType::Public;
        let tag = NoteTag::with_account_target(self.target);
        let mut payload = vec![
            self.target.suffix(),
            self.target.prefix().as_felt(),
            Felt::from(tag),
            Felt::from(note_type),
        ];
        payload.extend(serial_number.iter());
        for asset_id in asset_ids {
            payload.extend(asset_id.to_word().iter());
        }

        let script_args = Hasher::hash_elements(&payload);
        let mut advice_map = AdviceMap::default();
        advice_map.insert(script_args, payload);

        (self.script.clone().with_advice_map(advice_map), script_args)
    }
}

struct PassThroughDataStore {
    account: Account,
    reference_block_header: BlockHeader,
    partial_blockchain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl PassThroughDataStore {
    fn new(
        account: Account,
        reference_block_header: BlockHeader,
        partial_blockchain: PartialBlockchain,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());

        Self {
            account,
            reference_block_header,
            partial_blockchain,
            mast_store,
        }
    }
}

impl DataStore for PassThroughDataStore {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<Result<(PartialAccount, BlockHeader, PartialBlockchain), DataStoreError>>
    {
        async move {
            if account_id != self.account.id()
                || !ref_blocks.contains(&self.reference_block_header.block_num())
            {
                return Err(DataStoreError::other("invalid pass-through transaction inputs"));
            }

            Ok((
                PartialAccount::from(&self.account),
                self.reference_block_header.clone(),
                self.partial_blockchain.clone(),
            ))
        }
    }

    fn get_foreign_account_inputs(
        &self,
        _foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async {
            Err(DataStoreError::other("pass-through transactions do not use foreign accounts"))
        }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        asset_ids: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            if account_id != self.account.id() || vault_root != self.account.vault().root() {
                return Err(DataStoreError::other("invalid pass-through account vault"));
            }

            Ok(asset_ids
                .into_iter()
                .map(|asset_id| self.account.vault().open(asset_id))
                .collect())
        }
    }

    fn get_storage_map_witness(
        &self,
        _account_id: AccountId,
        _map_root: Word,
        _map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async { Err(DataStoreError::other("pass-through transactions do not use storage maps")) }
    }

    fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async { Ok(None) }
    }
}

impl MastForestStore for PassThroughDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}

#[cfg(test)]
mod tests {
    use miden_node_store::genesis::pass_through::build_pass_through_account;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::transaction::OutputNote;
    use miden_standards::note::TxFeeNote;
    use miden_testing::MockChain;

    use super::*;

    #[tokio::test]
    async fn converts_fee_notes_into_one_p2id_note() -> anyhow::Result<()> {
        let pass_through_account = build_pass_through_account()?;
        let mut chain_builder = MockChain::builder();
        chain_builder.add_account(pass_through_account.clone())?;
        let chain = chain_builder.build()?;

        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        let serial_number = Word::from([11_u32, 12, 13, 14]);
        let asset = FungibleAsset::mock(10);
        let fee_note = TxFeeNote::builder()
            .sender(ACCOUNT_ID_SENDER.try_into()?)
            .serial_number(Word::from([1_u32, 2, 3, 4]))
            .asset(asset)
            .build()?;

        let builder = PassThroughTransactionBuilder::new(target)?;
        let executed = builder
            .execute(
                vec![fee_note.into()],
                serial_number,
                chain.latest_block_header(),
                chain.latest_partial_blockchain(),
            )
            .await?;
        let transaction = PassThroughTransactionBuilder::prove(executed)?;

        assert_eq!(transaction.account_id(), pass_through_account.id());
        assert_eq!(
            transaction.account_update().initial_state_commitment(),
            transaction.account_update().final_state_commitment(),
        );
        assert_eq!(transaction.input_notes().num_notes(), 1);
        assert_eq!(transaction.output_notes().num_notes(), 1);

        let OutputNote::Public(output_note) = transaction.output_notes().get_note(0) else {
            panic!("the batch builder output note must be public");
        };
        let expected_recipient = P2idNoteStorage::new(target).into_recipient(serial_number);
        assert_eq!(output_note.recipient().digest(), expected_recipient.digest());
        assert_eq!(output_note.assets().iter().copied().collect::<Vec<_>>(), vec![asset]);

        Ok(())
    }
}
