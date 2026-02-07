use std::sync::Arc;

use miden_node_utils::fee::test_fee_params;
use miden_protocol::Word;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountBuilder, AccountStorageMode, AccountType};
use miden_protocol::block::{BlockBody, BlockHeader, BlockNoteTree, BlockNumber, SignedBlock};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::transaction::{OrderedTransactionHeaders, TransactionKernel};
use miden_standards::account::auth::AuthFalcon512Rpo;
use miden_standards::code_builder::CodeBuilder;
use tempfile::tempdir;

use super::State;
use crate::errors::ApplyBlockError;
use crate::genesis::GenesisState;
use crate::server::Store;

fn build_genesis_state() -> GenesisState<SecretKey> {
    let component_code = "pub proc foo push.1 end";
    let account_component_code = CodeBuilder::default()
        .compile_component_code("foo::interface", component_code)
        .unwrap();
    let account_component =
        miden_protocol::account::AccountComponent::new(account_component_code, Vec::new())
            .unwrap()
            .with_supports_all_types();

    let account = AccountBuilder::new([1u8; 32])
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_component(account_component)
        .with_auth_component(AuthFalcon512Rpo::new(PublicKeyCommitment::from(Word::empty())))
        .build_existing()
        .unwrap();

    GenesisState::new(vec![account], test_fee_params(), 1, 0, SecretKey::new())
}

async fn build_block(state: &State) -> SignedBlock {
    let body = BlockBody::new_unchecked(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        OrderedTransactionHeaders::new_unchecked(Vec::new()),
    );
    let note_root = BlockNoteTree::empty().root();
    let tx_commitment = body.transactions().commitment();

    let (chain_commitment, account_root, nullifier_root) = {
        let inner = state.inner.read().await;
        (
            inner.blockchain.peaks().hash_peaks(),
            inner.account_tree.root_latest(),
            inner.nullifier_tree.root(),
        )
    };

    let prev_block_commitment = state
        .db
        .select_block_header_by_block_num(None)
        .await
        .unwrap()
        .expect("genesis header should exist")
        .commitment();

    let signer = SecretKey::new();
    let header = BlockHeader::new(
        0,
        prev_block_commitment,
        BlockNumber::GENESIS.child(),
        chain_commitment,
        account_root,
        nullifier_root,
        note_root,
        tx_commitment,
        TransactionKernel.to_commitment(),
        signer.public_key(),
        test_fee_params(),
        0,
    );

    let signature = signer.sign(header.commitment());
    SignedBlock::new_unchecked(header, body, signature)
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_block_rejects_concurrent_writers() {
    let temp = tempdir().unwrap();
    Store::bootstrap(build_genesis_state(), temp.path()).unwrap();

    let (termination_ask, _termination_signal) = tokio::sync::mpsc::channel(1);
    let state = Arc::new(State::load(temp.path(), termination_ask).await.unwrap());

    let permit = state.writer.try_acquire().expect("writer permit should be free");

    let second_result = state.apply_block(build_block(&state).await).await;
    assert!(matches!(second_result, Err(ApplyBlockError::ConcurrentWrite)));

    drop(permit);

    let first_result = state.apply_block(build_block(&state).await).await;
    assert!(first_result.is_ok(), "first apply_block should succeed");
}
