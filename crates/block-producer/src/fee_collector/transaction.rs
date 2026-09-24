use std::collections::BTreeSet;
use std::num::NonZeroU16;

use miden_node_store::state::StateView;
use miden_objects::account_file::AccountFile;
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
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
use miden_standards::tx_script::ExpirationTransactionScript;
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

use super::faucet::FeeFaucet;

/// Builds transactions that deploy the fee collector or convert fee notes into one P2ID note.
#[derive(Clone)]
pub(crate) struct FeeCollectorTransactionBuilder {
    account: Account,
    target: AccountId,
    authenticator: BasicAuthenticator,
    fee_faucet: FeeFaucet,
}

impl FeeCollectorTransactionBuilder {
    pub(crate) async fn new(
        target: AccountId,
        account_file: AccountFile,
        view: &StateView,
    ) -> anyhow::Result<Self> {
        let (account, auth_secret_keys) = account_file.into_parts();
        let auth_root = AuthTxFeeCollector::code()
            .procedure_roots()
            .next()
            .expect("the fee collector exports its authentication procedure");
        anyhow::ensure!(
            account.code().procedures().first() == Some(&auth_root),
            "fee collector account must use AuthTxFeeCollector",
        );
        anyhow::ensure!(
            account.vault().is_empty(),
            "fee collector account must have an empty vault",
        );
        let public_key = account.storage().get_item(AuthTxFeeCollector::public_key_slot())?;
        let signature_scheme =
            account.storage().get_item(AuthTxFeeCollector::signature_scheme_slot())?;
        anyhow::ensure!(
            auth_secret_keys.iter().any(|key| {
                Word::from(key.public_key().to_commitment()) == public_key
                    && Word::from([key.auth_scheme().as_u8(), 0, 0, 0]) == signature_scheme
            }),
            "fee collector account file must contain its signing key",
        );
        let authenticator = BasicAuthenticator::new(&auth_secret_keys);
        let fee_faucet = FeeFaucet::load(view).await?;

        Ok(Self {
            account,
            target,
            authenticator,
            fee_faucet,
        })
    }

    pub(crate) async fn execute(
        &self,
        notes: Vec<Note>,
        reference_block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_blockchain: PartialBlockchain,
        view: &StateView,
    ) -> anyhow::Result<ExecutedTransaction> {
        let asset_ids = notes
            .iter()
            .flat_map(|note| note.assets().iter())
            .map(Asset::id)
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            asset_ids.len() <= NoteAssets::MAX_NUM_ASSETS,
            "fee collector transaction names {} assets but at most {} fit into one note",
            asset_ids.len(),
            NoteAssets::MAX_NUM_ASSETS,
        );

        let notes = InputNotes::from_unauthenticated_notes(notes)?;
        let auth_args = AuthTxFeeCollector::auth_args(self.target, NoteType::Public);
        let serial_number = AuthTxFeeCollector::derive_serial_number(auth_args, notes.commitment());
        let mut tx_args = TransactionArgs::new(AdviceMap::default()).with_auth_args(auth_args);
        if self.account.is_new() {
            let script = ExpirationTransactionScript::new(NonZeroU16::new(30).unwrap());
            tx_args = tx_args.with_tx_script_and_args(script.into(), script.tx_script_args());
        }
        let output_note_recipient = P2idNoteStorage::new(self.target).into_recipient(serial_number);
        tx_args.extend_advice_map(output_note_recipient.to_advice_map_entries());
        let data_store = FeeCollectorDataStore::new(
            self.account.clone(),
            reference_block_header,
            protocol_config,
            partial_blockchain,
            &self.fee_faucet,
            view,
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

    pub(crate) fn prove(transaction: ExecutedTransaction) -> anyhow::Result<ProvenTransaction> {
        Ok(LocalTransactionProver::default().prove(transaction)?)
    }
}

struct FeeCollectorDataStore<'a> {
    account: Account,
    reference_block_header: BlockHeader,
    protocol_config: ProtocolConfig,
    partial_blockchain: PartialBlockchain,
    mast_store: TransactionMastStore,
    fee_faucet: &'a FeeFaucet,
    view: &'a StateView,
}

impl<'a> FeeCollectorDataStore<'a> {
    fn new(
        account: Account,
        reference_block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        partial_blockchain: PartialBlockchain,
        fee_faucet: &'a FeeFaucet,
        view: &'a StateView,
    ) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(account.code());
        mast_store.load_account_code(&fee_faucet.code);

        Self {
            account,
            reference_block_header,
            protocol_config,
            partial_blockchain,
            mast_store,
            fee_faucet,
            view,
        }
    }
}

impl DataStore for FeeCollectorDataStore<'_> {
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
                return Err(DataStoreError::other("invalid fee collector transaction inputs"));
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
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        async move {
            if foreign_account_id != self.fee_faucet.id
                || ref_block != self.reference_block_header.block_num()
            {
                return Err(DataStoreError::other("invalid native faucet request"));
            }
            self.fee_faucet.account_inputs(self.view, ref_block).await.map_err(|error| {
                DataStoreError::Other {
                    error_msg: "failed to fetch native faucet account inputs".into(),
                    source: Some(error.into()),
                }
            })
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
                return Err(DataStoreError::other("invalid fee collector account vault"));
            }

            Ok(asset_ids
                .into_iter()
                .map(|asset_id| self.account.vault().open(asset_id))
                .collect())
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            if account_id != self.fee_faucet.id {
                return Err(DataStoreError::other("invalid native faucet request"));
            }
            self.fee_faucet
                .storage_map_witness(
                    self.view,
                    self.reference_block_header.block_num(),
                    map_root,
                    map_key,
                )
                .await
                .map_err(|error| DataStoreError::Other {
                    error_msg: "failed to fetch native faucet storage witness".into(),
                    source: Some(error.into()),
                })
        }
    }

    fn get_note_script(
        &self,
        _script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        async { Ok(None) }
    }
}

impl MastForestStore for FeeCollectorDataStore<'_> {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use miden_node_store::state::{BlockWriter, State};
    use miden_node_utils::genesis::GenesisBlock;
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::account::{AccountBuilder, AccountType};
    use miden_protocol::asset::{AssetAmount, FungibleAsset};
    use miden_protocol::block::{BlockSignatures, SignedBlock};
    use miden_protocol::testing::account_id::{
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_SENDER,
    };
    use miden_protocol::transaction::{OutputNote, TransactionVerifier};
    use miden_standards::account::access::{Authority, Pausable};
    use miden_standards::account::faucets::{FungibleFaucet, TokenName};
    use miden_standards::account::policies::{
        BlocklistManager,
        BurnPolicy,
        MintPolicy,
        TokenPolicyManager,
        TransferPolicy,
    };
    use miden_standards::code_builder::CodeBuilder;
    use miden_standards::errors::standards::ERR_ACCOUNT_IS_BLOCKED;
    use miden_standards::note::TxFeeNote;
    use miden_testing::{AccountState, Auth, MockChain, assert_transaction_executor_error};
    use miden_tx::TransactionExecutorError;

    use super::*;
    use crate::test_utils::{mock_collection_account, mock_native_faucet};

    #[tokio::test(flavor = "multi_thread")]
    async fn deploys_without_funds_and_collects_fee_notes_without_changing_account_state()
    -> anyhow::Result<()> {
        let faucet = mock_native_faucet();
        let mut chain = MockChain::builder().verification_base_fee(1).fee_faucet_id(faucet.id());
        chain.add_account(faucet.clone())?;
        let mut chain = chain.build()?;
        let directory = tempfile::tempdir()?;
        bootstrap(&chain, directory.path())?;
        let (state, mut writer, _proof_writer) = State::for_tests(directory.path()).await;
        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        let mut builder =
            FeeCollectorTransactionBuilder::new(target, mock_collection_account(), &state.view())
                .await?;
        assert!(builder.account.is_new());
        assert!(builder.account.vault().is_empty());
        let executed = builder
            .execute(
                Vec::new(),
                chain.latest_block_header(),
                chain.protocol_config().clone(),
                chain.latest_partial_blockchain(),
                &state.view(),
            )
            .await?;
        let deployment = FeeCollectorTransactionBuilder::prove(executed)?;
        let _outcome = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
            .verify(&deployment)?;
        assert_eq!(deployment.account_update().initial_state_commitment(), Word::empty());
        assert_eq!(deployment.input_notes().num_notes(), 0);
        assert_eq!(deployment.output_notes().num_notes(), 0);
        assert_eq!(deployment.expiration_block_num(), chain.latest_block_header().block_num() + 30);
        builder.account.set_nonce(miden_protocol::ONE)?;
        assert_eq!(
            deployment.account_update().final_state_commitment(),
            builder.account.to_commitment()
        );
        chain.add_pending_proven_transaction(deployment);
        chain.prove_next_block()?;
        let (header, body, signatures, _) = chain.latest_block().into_parts();
        writer.apply_block(SignedBlock::new(header, body, signatures)?, None).await?;

        for amounts in [vec![10, 20], vec![0]] {
            let notes = amounts
                .iter()
                .enumerate()
                .map(|(index, amount)| {
                    TxFeeNote::builder()
                        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
                        .serial_number(Word::from([u32::try_from(index).unwrap(), 2, 3, 4]))
                        .asset(FungibleAsset::new(faucet.id(), *amount).unwrap())
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
                    &state.view(),
                )
                .await?;
            let transaction = FeeCollectorTransactionBuilder::prove(executed)?;
            let _outcome = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
                .verify(&transaction)?;

            assert_eq!(transaction.account_id(), builder.account.id());
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
                vec![FungibleAsset::new(faucet.id(), amounts.iter().sum())?.into()],
            );
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fee_collection_uses_updated_native_faucet_blocklist() -> anyhow::Result<()> {
        for blocked in [false, true] {
            let (mut account, auth_secret_keys) = mock_collection_account().into_parts();
            account.set_nonce(miden_protocol::ONE)?;
            let collector = AccountFile::new(account, auth_secret_keys);
            let collector_id = collector.account().id();
            let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
            let blocked_account = if blocked { target } else { collector_id };
            let faucet = FungibleFaucet::builder()
                .name(TokenName::new("Native")?)
                .symbol("NAT".try_into()?)
                .decimals(6)
                .max_supply(AssetAmount::new(1_000_000)?)
                .build()?;
            let mut chain = MockChain::builder().verification_base_fee(0);
            let faucet = chain.add_account_from_builder(
                Auth::basic_ecdsa(),
                AccountBuilder::new([43; 32])
                    .account_type(AccountType::Public)
                    .with_component(faucet)
                    .with_component(Authority::AuthControlled)
                    .with_components(
                        TokenPolicyManager::builder()
                            .active_mint_policy(MintPolicy::allow_all())
                            .active_burn_policy(BurnPolicy::allow_all())
                            .active_send_policy(TransferPolicy::with_basic_blocklist([
                                blocked_account,
                            ]))
                            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                            .build(),
                    )
                    .with_component(Pausable::unpaused())
                    .with_component(BlocklistManager),
                AccountState::Exists,
            )?;
            chain.add_account(collector.account().clone())?;
            let mut chain = chain.fee_faucet_id(faucet.id()).build()?;
            let directory = tempfile::tempdir()?;
            bootstrap(&chain, directory.path())?;
            let (state, mut writer, _proof_writer) = State::for_tests(directory.path()).await;
            let asset = FungibleAsset::new(faucet.id(), 20)?;
            let note = TxFeeNote::builder()
                .sender(ACCOUNT_ID_SENDER.try_into()?)
                .serial_number(Word::from([1, 2, 3, 4u32]))
                .asset(asset)
                .build()?;
            let builder =
                FeeCollectorTransactionBuilder::new(target, collector, &state.view()).await?;
            Box::pin(update_blocklist(&mut chain, &mut writer, faucet.id(), collector_id, blocked))
                .await?;
            let result = builder
                .execute(
                    vec![note.into()],
                    chain.latest_block_header(),
                    chain.protocol_config().clone(),
                    chain.latest_partial_blockchain(),
                    &state.view(),
                )
                .await;
            if blocked {
                let error = result.unwrap_err().downcast::<TransactionExecutorError>()?;
                assert_transaction_executor_error!(Err::<(), _>(error), ERR_ACCOUNT_IS_BLOCKED);
            } else {
                let executed = result?;
                assert_eq!(
                    executed.final_account().to_commitment(),
                    builder.account.to_commitment()
                );
                assert_eq!(executed.output_notes().num_notes(), 1);
                let note = executed.output_notes().get_note(0);
                assert_eq!(note.assets().iter().copied().collect::<Vec<_>>(), vec![asset.into()]);
            }
        }
        Ok(())
    }

    async fn update_blocklist(
        chain: &mut MockChain,
        writer: &mut BlockWriter,
        faucet_id: AccountId,
        account_id: AccountId,
        blocked: bool,
    ) -> anyhow::Result<()> {
        let operation = if blocked { "block_account" } else { "unblock_account" };
        let script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
            r"
            use miden::standards::faucets::policies::transfer::blocklist::manager
            @transaction_script
            pub proc main
                padw padw padw push.0.0
                push.{prefix}.{suffix}
                call.manager::{operation}
                dropw dropw dropw dropw
            end
            ",
            prefix = account_id.prefix().as_felt(),
            suffix = account_id.suffix(),
        ))?;
        let executed =
            chain.build_transaction(faucet_id).tx_script(script).build()?.execute().await?;
        chain.add_pending_executed_transaction(&executed)?;
        chain.prove_next_block()?;
        let (header, body, signatures, _) = chain.latest_block().into_parts();
        writer.apply_block(SignedBlock::new(header, body, signatures)?, None).await?;
        Ok(())
    }

    fn bootstrap(chain: &MockChain, path: &Path) -> anyhow::Result<()> {
        let genesis = chain.latest_block();
        State::bootstrap(
            GenesisBlock::new(
                SignedBlock::new(
                    genesis.header().clone(),
                    genesis.body().clone(),
                    BlockSignatures::new(Vec::new())?,
                )?,
                chain.protocol_config().clone(),
            )?,
            path,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_missing_or_mismatched_signing_keys() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        bootstrap(&MockChain::builder().build()?, directory.path())?;
        let (state, ..) = State::for_tests(directory.path()).await;
        let (account, _) = mock_collection_account().into_parts();
        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        for keys in [vec![], vec![AuthSecretKey::new_falcon512_poseidon2()]] {
            let result = FeeCollectorTransactionBuilder::new(
                target,
                AccountFile::new(account.clone(), keys),
                &state.view(),
            )
            .await;
            let error = result.err().expect("the collector must require its own signing key");
            assert!(error.to_string().contains("signing key"));
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_an_ordinary_wallet_as_the_collector() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        bootstrap(&MockChain::builder().build()?, directory.path())?;
        let (state, ..) = State::for_tests(directory.path()).await;
        let account = MockChain::builder().add_existing_wallet(Auth::basic_ecdsa())?;
        let target = ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE.try_into()?;
        let result = FeeCollectorTransactionBuilder::new(
            target,
            AccountFile::new(account, vec![]),
            &state.view(),
        )
        .await;
        let error = result.err().expect("an ordinary wallet must not collect batch fees");
        assert!(error.to_string().contains("AuthTxFeeCollector"));
        Ok(())
    }
}
