use std::collections::BTreeSet;

use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountFile,
    AccountId,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
};
use miden_protocol::asset::{Asset, AssetId, AssetWitness};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteAssets, NoteScript, NoteScriptRoot, NoteType};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    AccountInputs,
    ExecutedTransaction,
    InputNotes,
    PartialBlockchain,
    ProvenTransaction,
    TransactionArgs,
};
use miden_protocol::vm::{AdviceMap, FutureMaybeSend};
use miden_standards::account::auth::AuthTxFeeCollector;
use miden_standards::note::P2idNoteStorage;
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

/// Builds the transaction that converts a batch's fee notes into one P2ID note.
#[derive(Clone)]
pub(super) struct PassThroughTransactionBuilder {
    account: Account,
    target: AccountId,
    authenticator: BasicAuthenticator,
}

impl PassThroughTransactionBuilder {
    pub(super) fn new(target: AccountId, account_file: AccountFile) -> anyhow::Result<Self> {
        let AccountFile { account, auth_secret_keys } = account_file;
        let auth_root = AuthTxFeeCollector::code()
            .procedure_roots()
            .next()
            .expect("the fee collector exports its authentication procedure");
        anyhow::ensure!(
            account.code().procedures().first() == Some(&auth_root),
            "pass-through account must use AuthTxFeeCollector",
        );
        anyhow::ensure!(
            !account.is_new() && account.vault().is_empty(),
            "pass-through account must be deployed and have an empty vault",
        );
        let public_key = account.storage().get_item(AuthTxFeeCollector::public_key_slot())?;
        let signature_scheme =
            account.storage().get_item(AuthTxFeeCollector::signature_scheme_slot())?;
        anyhow::ensure!(
            auth_secret_keys.iter().any(|key| {
                Word::from(key.public_key().to_commitment()) == public_key
                    && Word::from([key.auth_scheme().as_u8(), 0, 0, 0]) == signature_scheme
            }),
            "pass-through account file must contain its signing key",
        );
        let authenticator = BasicAuthenticator::new(&auth_secret_keys);

        Ok(Self { account, target, authenticator })
    }

    pub(super) async fn execute(
        &self,
        notes: Vec<Note>,
        reference_block_header: BlockHeader,
        protocol_config: ProtocolConfig,
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

        let notes = InputNotes::from_unauthenticated_notes(notes)?;
        let auth_args = AuthTxFeeCollector::auth_args(self.target, NoteType::Public);
        let serial_number = AuthTxFeeCollector::derive_serial_number(auth_args, notes.commitment());
        let mut tx_args = TransactionArgs::new(AdviceMap::default()).with_auth_args(auth_args);
        let output_note_recipient = P2idNoteStorage::new(self.target).into_recipient(serial_number);
        tx_args.extend_advice_map(output_note_recipient.to_advice_map_entries());
        let data_store = PassThroughDataStore::new(
            self.account.clone(),
            reference_block_header,
            protocol_config,
            partial_blockchain,
        );

        Ok(TransactionExecutor::new(&data_store)
            .with_authenticator(&self.authenticator)
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
}

struct PassThroughDataStore {
    account: Account,
    reference_block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_blockchain: PartialBlockchain,
    mast_store: TransactionMastStore,
}

impl PassThroughDataStore {
    fn new(
        account: Account,
        reference_block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_blockchain: PartialBlockchain,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());

        Self {
            account,
            reference_block_header,
            protocol_config,
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
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        async move {
            if account_id != self.account.id()
                || !ref_blocks.contains(&self.reference_block_header.block_num())
            {
                return Err(DataStoreError::other("invalid pass-through transaction inputs"));
            }

            Ok((
                PartialAccount::from(&self.account),
                self.reference_block_header.clone(),
                self.protocol_config.clone(),
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
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::transaction::{OutputNote, TransactionVerifier};
    use miden_standards::note::TxFeeNote;
    use miden_testing::{Auth, MockChain};

    use super::*;

    #[tokio::test]
    async fn collects_fee_notes_including_zero_fees_without_changing_account_state()
    -> anyhow::Result<()> {
        let (pass_through_account, key) = build_pass_through_account()?;
        let mut chain_builder = MockChain::builder();
        chain_builder.add_account(pass_through_account.clone())?;
        let chain = chain_builder.build()?;

        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        let builder = PassThroughTransactionBuilder::new(
            target,
            AccountFile::new(
                pass_through_account.clone(),
                vec![AuthSecretKey::Falcon512Poseidon2(key)],
            ),
        )?;
        for amounts in [vec![10, 20], vec![0]] {
            let notes = amounts
                .iter()
                .enumerate()
                .map(|(index, amount)| {
                    TxFeeNote::builder()
                        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
                        .serial_number(Word::from([u32::try_from(index).unwrap(), 2, 3, 4]))
                        .asset(FungibleAsset::mock(*amount))
                        .build()
                        .map(Note::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let serial_number = AuthTxFeeCollector::derive_serial_number(
                AuthTxFeeCollector::auth_args(target, NoteType::Public),
                InputNotes::from_unauthenticated_notes(notes.clone())?.commitment(),
            );
            let executed = builder
                .execute(
                    notes,
                    chain.latest_block_header(),
                    chain.protocol_config().clone(),
                    chain.latest_partial_blockchain(),
                )
                .await?;
            let transaction = PassThroughTransactionBuilder::prove(executed)?;
            let outcome = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
                .verify(&transaction)?;
            assert!(outcome.is_complete());

            assert_eq!(transaction.account_id(), pass_through_account.id());
            assert_eq!(
                transaction.account_update().initial_state_commitment(),
                transaction.account_update().final_state_commitment(),
            );
            assert_eq!(usize::from(transaction.input_notes().num_notes()), amounts.len());
            assert_eq!(transaction.output_notes().num_notes(), 1);

            let OutputNote::Public(output_note) = transaction.output_notes().get_note(0) else {
                panic!("the batch builder output note must be public");
            };
            let expected_recipient = P2idNoteStorage::new(target).into_recipient(serial_number);
            assert_eq!(output_note.recipient().digest(), expected_recipient.digest());
            assert_eq!(
                output_note.assets().iter().copied().collect::<Vec<_>>(),
                vec![FungibleAsset::mock(amounts.iter().sum())],
            );
        }

        Ok(())
    }

    #[test]
    fn rejects_missing_or_mismatched_signing_keys() -> anyhow::Result<()> {
        let (account, _) = build_pass_through_account()?;
        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        for keys in [vec![], vec![AuthSecretKey::new_falcon512_poseidon2()]] {
            let result =
                PassThroughTransactionBuilder::new(target, AccountFile::new(account.clone(), keys));
            let error = result.err().expect("the collector must require its own signing key");
            assert!(error.to_string().contains("signing key"));
        }

        Ok(())
    }

    #[test]
    fn rejects_an_ordinary_wallet_as_the_collector() -> anyhow::Result<()> {
        let account = MockChain::builder().add_existing_wallet(Auth::basic_ecdsa())?;
        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        let result = PassThroughTransactionBuilder::new(target, AccountFile::new(account, vec![]));
        let error = result.err().expect("an ordinary wallet must not collect batch fees");
        assert!(error.to_string().contains("AuthTxFeeCollector"));
        Ok(())
    }
}
