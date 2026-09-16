use std::collections::BTreeSet;

use miden_node_proto::clients::{Builder, RemoteProverClient};
use miden_node_proto::generated::remote_prover::proof::Proof;
use miden_node_proto::generated::remote_prover::proof_request::Request;
use miden_node_proto::{BuildUnchecked, DecodeMessage, generated as proto};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountId, AccountType, AccountUpdateDetails};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::{
    OutputNote,
    ProvenTransaction,
    TransactionInputs,
    TransactionVerifier,
};
use miden_protocol::{ONE, Word};
use miden_standards::account::auth::Approver;
use miden_standards::account::wallets::create_basic_wallet;
use miden_standards::note::{P2idNote, TxFeeNote};
use miden_testing::MockChain;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use super::transaction::CollectionContext;
use super::*;

struct TransactionProver;

#[tonic::async_trait]
impl miden_node_proto::server::remote_prover_api::Prove for TransactionProver {
    type Input = TransactionInputs;
    type Output = ProvenTransaction;

    fn decode(request: proto::remote_prover::ProofRequest) -> tonic::Result<Self::Input> {
        let Some(Request::Transaction(inputs)) = request.request else {
            return Err(tonic::Status::invalid_argument("expected transaction inputs"));
        };
        inputs
            .decode_fields()
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))?
            .build_unchecked()
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
    }

    fn encode(transaction: Self::Output) -> tonic::Result<proto::remote_prover::Proof> {
        Ok(proto::remote_prover::Proof {
            proof: Some(Proof::Transaction(transaction.into())),
        })
    }

    async fn handle(
        &self,
        inputs: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        spawn_blocking_in_current_span(move || {
            miden_tx::LocalTransactionProver::default().prove(inputs)
        })
        .await
        .map_err(|error| tonic::Status::internal(error.to_string()))?
        .map_err(|error| tonic::Status::internal(error.to_string()))
    }
}

async fn start_prover(
    shutdown: CancellationToken,
) -> anyhow::Result<(
    RemoteProverClient,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = Builder::new(format!("http://{}", listener.local_addr()?).parse()?)
        .without_tls()
        .with_timeout(Duration::from_secs(30))
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RemoteProverClient>();
    let server = tonic::transport::Server::builder()
        .add_service(miden_node_proto::server::remote_prover_api::service(TransactionProver))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown.cancelled_owned());
    Ok((client, tokio::spawn(server)))
}

fn fixture(fee: u32) -> anyhow::Result<(AccountFile, MockChain)> {
    fixture_with_scheme(fee, AuthScheme::EcdsaK256Keccak)
}

fn fixture_with_scheme(fee: u32, scheme: AuthScheme) -> anyhow::Result<(AccountFile, MockChain)> {
    let key = AuthSecretKey::with_scheme(scheme)?;
    let approver = Approver::new(key.public_key().to_commitment(), key.auth_scheme());
    let mut account = create_basic_wallet([7; 32], approver, AccountType::Public)?;
    account.set_nonce(ONE)?;
    let mut builder = MockChain::builder().verification_base_fee(fee);
    builder.add_account(account.clone())?;
    Ok((AccountFile::new(account, vec![key]), builder.build()?))
}

fn context(account: &AccountFile, chain: &MockChain) -> CollectionContext {
    CollectionContext {
        account: account.account.clone(),
        block_header: chain.latest_block_header(),
        protocol_config: chain.protocol_config().clone(),
        blockchain: chain.latest_partial_blockchain(),
    }
}

fn note(account: AccountId, faucet: AccountId, serial: u32, amount: u64) -> Note {
    P2idNote::builder()
        .sender(ACCOUNT_ID_SENDER.try_into().unwrap())
        .target(account)
        .serial_number(Word::from([serial, 2, 3, 4]))
        .note_type(NoteType::Public)
        .asset(FungibleAsset::new(faucet, amount).unwrap())
        .build()
        .unwrap()
        .into()
}

#[tokio::test]
async fn collects_into_the_wallet_and_outputs_a_fee_note_including_when_fees_are_zero()
-> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let (prover, server) = start_prover(shutdown.clone()).await?;
    for (fee, scheme, amount) in [
        (0, AuthScheme::EcdsaK256Keccak, 100_000),
        (1, AuthScheme::EcdsaK256Keccak, 100_000),
        (0, AuthScheme::Falcon512Poseidon2, 0),
        (1, AuthScheme::Falcon512Poseidon2, 100_000),
    ] {
        let (account, chain) = fixture_with_scheme(fee, scheme)?;
        let notes = vec![
            note(account.account.id(), chain.fee_faucet_id(), 1, amount),
            note(account.account.id(), chain.fee_faucet_id(), 2, amount * 2),
        ];
        let executed =
            Box::pin(execute(context(&account, &chain), notes.clone(), &account.auth_secret_keys))
                .await?;
        let tx = transaction::prove(&prover, executed.tx_inputs()).await?;
        miden_node_block_producer::ensure_transaction_has_fee(
            &tx,
            chain.protocol_config().fee_asset_id(),
        )?;
        let _verification_outcome =
            TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL).verify(&tx)?;
        assert_eq!(
            tx.nullifiers().collect::<BTreeSet<_>>(),
            notes.iter().map(Note::nullifier).collect()
        );
        assert_eq!(tx.expiration_block_num().as_u32(), tx.ref_block_num().as_u32() + 30);
        assert_eq!(tx.output_notes().num_notes(), 1);
        let OutputNote::Public(output) = tx.output_notes().get_note(0) else {
            panic!("fee note must be public");
        };
        assert_eq!(output.as_note().script().root(), TxFeeNote::script_root());
        let paid_fee = output.assets().iter().next().unwrap().unwrap_fungible().amount().as_u64();
        assert_eq!(paid_fee == 0, fee == 0);
        let AccountUpdateDetails::Public(patch) = tx.account_update().details() else {
            panic!("wallet must be public");
        };
        let mut updated = account.account;
        updated.apply_patch(patch)?;
        assert_eq!(
            updated.vault().get_balance(chain.protocol_config().fee_asset_id())?.as_u64(),
            amount * 3 - paid_fee
        );
        assert_eq!(updated.nonce(), ONE + ONE);
    }
    shutdown.cancel();
    server.await??;
    Ok(())
}

#[test]
fn rejects_missing_or_wrong_signing_keys() -> anyhow::Result<()> {
    let (account, _) = fixture(0)?;
    assert!(validate_account(&account.account, &[]).is_err());
    let wrong_key = AuthSecretKey::with_scheme(AuthScheme::EcdsaK256Keccak)?;
    assert!(validate_account(&account.account, &[wrong_key]).is_err());
    Ok(())
}

#[test]
fn rejects_private_and_undeployed_wallets() -> anyhow::Result<()> {
    let key = AuthSecretKey::with_scheme(AuthScheme::EcdsaK256Keccak)?;
    for account_type in [AccountType::Public, AccountType::Private] {
        let approver = Approver::new(key.public_key().to_commitment(), key.auth_scheme());
        let mut account = create_basic_wallet([8; 32], approver, account_type)?;
        if account_type == AccountType::Private {
            account.set_nonce(ONE)?;
        }
        assert!(validate_account(&account, std::slice::from_ref(&key)).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn rejects_collection_when_the_wallet_cannot_pay_the_transaction_fee() -> anyhow::Result<()> {
    let (account, chain) = fixture(1)?;
    let input = note(account.account.id(), chain.fee_faucet_id(), 1, 0);
    assert!(
        Box::pin(execute(context(&account, &chain), vec![input], &account.auth_secret_keys))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[expect(clippy::too_many_lines, reason = "the test includes the chain and RPC fixtures")]
async fn collection_attempts_refresh_the_wallet_and_unspent_notes_from_store() -> anyhow::Result<()>
{
    use miden_node_proto::clients::RpcClient;
    use miden_node_rpc::{Rpc, RpcMode};
    use miden_node_store::State;
    use miden_node_store::genesis::GenesisBlock;
    use miden_node_utils::clap::{GrpcOptions, StorageOptions};
    use miden_protocol::block::{BlockSignatures, SignedBlock};
    use miden_protocol::transaction::RawOutputNote;
    use miden_standards::tx_script::SendNotesTransactionScript;
    use miden_testing::Auth;

    let (account, original) = fixture(0)?;
    let mut builder = MockChain::builder();
    builder.add_account(account.account.clone())?;
    let sender = builder.add_existing_wallet_with_assets(
        Auth::basic_ecdsa(),
        [FungibleAsset::new(original.fee_faucet_id(), 10_200)?.into()],
    )?;
    let inputs = (0..102)
        .map(|serial| {
            P2idNote::builder()
                .sender(sender.id())
                .target(account.account.id())
                .serial_number(Word::from([serial, 2u32, 3, 4]))
                .note_type(NoteType::Public)
                .asset(FungibleAsset::new(original.fee_faucet_id(), 100).unwrap())
                .build()
                .map(Note::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut chain = builder.build()?;
    let genesis = chain.latest_block();
    let script = SendNotesTransactionScript::new(
        &sender.code_interface(),
        &inputs.iter().cloned().map(Into::into).collect::<Vec<_>>(),
    )?;
    let creation = Box::pin(
        chain
            .build_transaction(sender.id())
            .send_notes_script(&script)
            .expected_output_notes(inputs.iter().cloned().map(RawOutputNote::Full).collect())
            .build()?
            .execute(),
    )
    .await?;
    chain.add_pending_executed_transaction(&creation)?;
    let creation_block = chain.prove_next_block()?;
    let executed = Box::pin(execute(
        context(&account, &chain),
        vec![inputs[0].clone()],
        &account.auth_secret_keys,
    ))
    .await?;
    chain.add_pending_executed_transaction(&executed)?;
    let block = chain.prove_next_block()?;

    let directory = tempfile::tempdir()?.keep();
    State::bootstrap(
        GenesisBlock::new(
            SignedBlock::new(
                genesis.header().clone(),
                genesis.body().clone(),
                BlockSignatures::new(vec![])?,
            )?,
            chain.protocol_config().clone(),
        )?,
        &directory,
    )?;
    let shutdown = CancellationToken::new();
    let (prover, prover_server) = start_prover(shutdown.clone()).await?;
    let (state, mut writer, proof_writer, writer_task) =
        State::load(&directory, StorageOptions::default())
            .await?
            .start(shutdown.clone());
    writer
        .apply_block(
            SignedBlock::new(
                creation_block.header().clone(),
                creation_block.body().clone(),
                creation_block.signatures().clone(),
            )?,
            None,
        )
        .await?;
    state
        .with_view(async |view| {
            writer
                .apply_block(
                    SignedBlock::new(
                        block.header().clone(),
                        block.body().clone(),
                        block.signatures().clone(),
                    )?,
                    None,
                )
                .await?;
            // The pinned view must include notes consumed by a later block.
            let notes = view.get_unspent_p2id_notes(account.account.id(), 102).await?;
            assert_eq!(
                notes.iter().map(Note::id).collect::<BTreeSet<_>>(),
                inputs.iter().map(Note::id).collect(),
            );
            anyhow::Ok(())
        })
        .await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = Builder::new(format!("http://{}", listener.local_addr()?).parse()?)
        .without_tls()
        .with_timeout(Duration::from_secs(10))
        .without_metadata_version()
        .with_metadata_genesis(genesis.header().commitment())
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();
    let rpc = Rpc {
        listener,
        state: Arc::clone(&state),
        mode: RpcMode::full_node(client, 0, None, writer, proof_writer),
        ntx_builder: None,
        grpc_options: GrpcOptions::test(),
        network_tx_auth: None,
    }
    .into_server()
    .await?;
    let client = CollectionRpc::new(rpc.api(), genesis.header(), Duration::from_secs(10));
    let collector = FeeCollector::new(state, client, prover.clone(), account.clone())?;
    let result =
        async {
            // The listener accepts connections but does not serve requests.
            let client = CollectionRpc::new(rpc.api(), genesis.header(), Duration::from_millis(10));
            let timeout_collector =
                FeeCollector::new(Arc::clone(&collector.state), client, prover, account.clone())?;
            let expiration_block = Some(block.header().block_num() + u32::from(EXPIRATION_BLOCKS));
            assert_eq!(timeout_collector.collect_fees().await?, expiration_block);
            drop(timeout_collector);
            drop(rpc);

            for _ in 0..2 {
                let (refreshed, notes) = collector.collection_inputs().await?;
                assert_eq!(
                    refreshed.account.to_commitment(),
                    executed.final_account().to_commitment(),
                );
                assert_eq!(refreshed.block_header, chain.latest_block_header());
                assert_eq!(refreshed.protocol_config, *chain.protocol_config());
                assert_eq!(
                    refreshed.blockchain.chain_length(),
                    chain.latest_block_header().block_num(),
                );
                assert_eq!(
                    notes.iter().map(Note::id).collect::<BTreeSet<_>>(),
                    inputs[1..].iter().map(Note::id).collect(),
                );
                assert_eq!(collector.collect_fees().await?, expiration_block);
            }
            anyhow::Ok(())
        }
        .await;
    shutdown.cancel();
    drop(collector);
    writer_task.await?;
    prover_server.await??;
    fs_err::remove_dir_all(directory)?;
    result
}
