use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::ExecutedTransaction;
use miden_testing::{Auth, MockChainBuilder};

use super::*;

async fn captured_execution() -> ExecutedTransaction {
    let mut builder = MockChainBuilder::new();
    let account = builder
        .add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })
        .unwrap();
    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
            .unwrap()
            .into();
    let note = builder
        .add_p2id_note(
            ACCOUNT_ID_SENDER.try_into().unwrap(),
            account.id(),
            &[asset],
            NoteType::Private,
        )
        .unwrap();
    let chain = builder.build().unwrap();
    Box::pin(
        chain
            .build_transaction(account.id())
            .authenticated_input_note(note.clone())
            .build()
            .unwrap()
            .execute(),
    )
    .await
    .unwrap()
}

async fn replay(
    inputs: TransactionInputs,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    let args = replay_args(&inputs);
    let store = TransactionInputsDataStore::new(inputs.clone());
    Box::pin(TransactionExecutor::<_, UnreachableAuth>::new(&store).execute_transaction(
        inputs.account().id(),
        inputs.ref_block(),
        inputs.input_notes().clone(),
        args,
    ))
    .await
}

#[tokio::test]
async fn replay_uses_captured_signatures_without_an_authenticator() {
    let executed = captured_execution().await;
    assert_ne!(executed.tx_inputs().signatures(), []);
    let replayed = replay(executed.tx_inputs().clone()).await.unwrap();
    assert_eq!(replayed.id(), executed.id());
    assert_eq!(replayed.final_account(), executed.final_account());
    assert_eq!(replayed.expiration_block_num(), executed.expiration_block_num());
    assert_eq!(replayed.output_notes(), executed.output_notes());
}

#[tokio::test]
async fn replay_rejects_missing_signatures() {
    let executed = captured_execution().await;
    let inputs = executed.tx_inputs();
    let unsigned = TransactionInputs::builder()
        .account(inputs.account().clone())
        .block_header(inputs.block_header().clone())
        .protocol_config(inputs.protocol_config().clone())
        .blockchain(inputs.blockchain().clone())
        .input_notes(inputs.input_notes().clone())
        .tx_args(inputs.tx_args().clone())
        .build()
        .unwrap();
    assert!(replay(unsigned).await.is_err());
}

#[tokio::test]
async fn replay_store_reports_missing_data_and_wrong_roots() {
    use std::collections::BTreeSet;

    use miden_protocol::Word;
    use miden_protocol::note::NoteScriptRoot;
    use miden_tx::DataStore;
    let executed = captured_execution().await;
    let inputs = executed.tx_inputs();
    let store = TransactionInputsDataStore::new(inputs.clone());
    assert!(
        store
            .get_note_script(NoteScriptRoot::from_raw(Word::empty()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_vault_asset_witnesses(inputs.account().id(), Word::empty(), BTreeSet::new(),)
            .await
            .is_err()
    );
    assert!(
        store
            .get_foreign_account_inputs(ACCOUNT_ID_SENDER.try_into().unwrap(), inputs.ref_block(),)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn replay_store_serves_foreign_state_scripts_and_witnesses() {
    use std::collections::BTreeSet;

    use miden_protocol::Word;
    use miden_protocol::account::AccountStorage;
    use miden_protocol::note::NoteScript;
    use miden_protocol::transaction::AccountInputs;
    use miden_tx::DataStore;
    let mut builder = MockChainBuilder::new();
    let auth = Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    };
    let native = builder.add_existing_wallet(auth.clone()).unwrap();
    let asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
            .unwrap()
            .into();
    let map = AccountStorage::mock_map();
    let (key, value) = map.entries().next().map(|(key, value)| (*key, *value)).unwrap();
    let foreign = builder
        .add_existing_mock_account_with_storage_and_assets(
            auth,
            [AccountStorage::mock_map_slot()],
            [asset],
        )
        .unwrap();
    let chain = builder.build().unwrap();
    let mut inputs = chain.get_transaction_inputs(&native, &[], &[]).unwrap();
    let (account, witness) = chain.get_foreign_account_inputs(foreign.id()).unwrap();
    inputs
        .add_foreign_account(AccountInputs::new((&account).into(), witness))
        .unwrap();
    inputs
        .add_asset_witnesses(foreign.id(), [account.vault().open(asset.id())])
        .unwrap();
    inputs.add_storage_map_witnesses(foreign.id(), [map.open(&key)]).unwrap();
    let script = NoteScript::mock();
    inputs.add_note_script(script.clone());
    let reference = inputs.ref_block();
    let store = TransactionInputsDataStore::new(inputs);
    assert_eq!(
        store
            .get_foreign_account_inputs(foreign.id(), reference)
            .await
            .unwrap()
            .account()
            .to_commitment(),
        foreign.to_commitment()
    );
    assert!(store.get_foreign_account_inputs(foreign.id(), reference.child()).await.is_err());
    assert_eq!(store.get_note_script(script.root()).await.unwrap(), Some(script));
    let assets = store
        .get_vault_asset_witnesses(
            foreign.id(),
            foreign.vault().root(),
            BTreeSet::from([asset.id()]),
        )
        .await
        .unwrap();
    assert_eq!(assets[0].find(asset.id()), Some(asset));
    let storage = store.get_storage_map_witness(foreign.id(), map.root(), key).await.unwrap();
    assert_eq!(storage.get(key), Some(value));
    assert!(store.get_storage_map_witness(foreign.id(), Word::empty(), key).await.is_err());
}

async fn captured_foreign_execution() -> ExecutedTransaction {
    use miden_protocol::account::{AccountBuilder, AccountType};
    use miden_protocol::asset::AssetAmount;
    use miden_protocol::note::{Note, PartialNote};
    use miden_standards::account::access::Authority;
    use miden_standards::account::faucets::{FungibleFaucet, TokenName};
    use miden_standards::account::policies::{
        BurnPolicy,
        MintPolicy,
        TokenPolicyManager,
        TransferPolicy,
    };
    use miden_standards::note::P2idNote;
    use miden_standards::tx_script::SendNotesTransactionScript;
    use miden_testing::AccountState;

    let mut builder = MockChainBuilder::new();
    let faucet = builder
        .add_account_from_builder(
            Auth::IncrNonce,
            AccountBuilder::new([7; 32])
                .account_type(AccountType::Public)
                .with_component(
                    FungibleFaucet::builder()
                        .name(TokenName::new("SYM").unwrap())
                        .symbol("SYM".try_into().unwrap())
                        .decimals(8)
                        .max_supply(AssetAmount::new(1_000).unwrap())
                        .build()
                        .unwrap(),
                )
                .with_component(Authority::AuthControlled)
                .with_components(
                    TokenPolicyManager::builder()
                        .active_mint_policy(MintPolicy::allow_all())
                        .active_burn_policy(BurnPolicy::allow_all())
                        .active_send_policy(TransferPolicy::empty_basic_blocklist())
                        .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                        .build(),
                ),
            AccountState::Exists,
        )
        .unwrap();
    let asset = FungibleAsset::new(faucet.id(), 100).unwrap();
    let native = builder
        .add_existing_wallet_with_assets(Auth::basic_ecdsa(), [asset.into()])
        .unwrap();
    let mut chain = builder.build().unwrap();
    chain.prove_next_block().unwrap();
    let note = Note::from(
        P2idNote::builder()
            .sender(native.id())
            .target(ACCOUNT_ID_SENDER.try_into().unwrap())
            .serial_number(miden_protocol::Word::from([1_u32, 2, 3, 4]))
            .asset(asset)
            .build()
            .unwrap(),
    );
    let script =
        SendNotesTransactionScript::new(&native.code_interface(), &[PartialNote::from(note)])
            .unwrap();
    Box::pin(
        chain
            .build_transaction(native.id())
            .foreign_accounts([chain.get_foreign_account_inputs(faucet.id()).unwrap()])
            .send_notes_script(&script)
            .build()
            .unwrap()
            .execute(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn replay_validates_captured_foreign_state_with_a_real_proof() {
    let executed = captured_foreign_execution().await;
    assert_eq!(executed.tx_inputs().foreign_accounts().len(), 1);
    let proven = miden_tx::LocalTransactionProver::default().prove(executed.clone()).unwrap();
    let effects = validate_transaction(proven.clone(), executed.tx_inputs().clone())
        .await
        .unwrap();
    assert_eq!(effects.transaction_id(), proven.id());
    assert_eq!(effects.logs_commitment(), proven.log_details().commitment());
    assert_eq!(effects.code_patch(), proven.code_patch());
}

#[tokio::test]
async fn replay_rejects_missing_foreign_account() {
    let executed = captured_foreign_execution().await;
    let inputs = executed.tx_inputs();
    let incomplete = TransactionInputs::builder()
        .account(inputs.account().clone())
        .block_header(inputs.block_header().clone())
        .protocol_config(inputs.protocol_config().clone())
        .blockchain(inputs.blockchain().clone())
        .input_notes(inputs.input_notes().clone())
        .tx_args(inputs.tx_args().clone())
        .signatures(inputs.signatures().to_vec())
        .build()
        .unwrap();
    assert!(replay(incomplete).await.is_err());
}
