use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_proto::domain::encryption::{
    TransactionEncryptionKeyInfo,
    TransactionEncryptionScheme,
    transaction_inputs_associated_data,
};
use miden_node_proto::generated::server::validator_api;
use miden_node_proto::{BuildUnchecked, DecodeMessage, generated as proto};
use miden_node_store::GenesisState;
use miden_node_store::state::State;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::genesis::GenesisBlock;
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::asset::AssetId;
use miden_protocol::block::{FeeParameters, ValidatorConfig};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::dsa::eddsa_25519_sha512::KeyExchangeKey;
use miden_protocol::crypto::ies::{SealedMessage, UnsealingKey};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{TransactionId, TransactionInputs, TransactionVerifier};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::http::Extensions;
use tonic::metadata::MetadataMap;

use super::*;
use crate::test_utils::{mock_collection_account, mock_native_faucet};

#[tokio::test(flavor = "multi_thread")]
async fn collector_deployment_proves_the_block_and_supports_a_new_collector() {
    let directory = tempfile::tempdir().unwrap();
    let signer = SigningKey::new();
    let genesis = genesis_with_faucet(&signer);
    let validator = Validator {
        signer,
        genesis: genesis.inner().header().commitment(),
        encryption_secret: KeyExchangeKey::read_from_bytes(&[7; 32]).unwrap(),
        transactions: Arc::new(Mutex::new(BTreeSet::new())),
        reject_transaction: Arc::new(AtomicBool::new(true)),
    };
    State::bootstrap(genesis, directory.path()).unwrap();
    let shutdown = CancellationToken::new();
    let (state, mut writer, mut proof_writer, writer_task) =
        State::load(directory.path(), StorageOptions::default())
            .await
            .unwrap()
            .start(shutdown.clone());
    let (url, server) = validator.clone().serve(shutdown.clone()).await;
    let validator_urls = vec![url];
    let account_file = mock_collection_account();
    let mut account = account_file.account().clone();
    account.set_nonce(ONE).unwrap();
    assert!(!collector_is_deployed(&state, &account).await.unwrap());

    assert!(
        Box::pin(deploy_fee_collector(
            &state,
            &mut writer,
            &mut proof_writer,
            account_file.clone(),
            validator_urls.clone(),
            Duration::from_secs(30)
        ))
        .await
        .is_err()
    );
    assert_eq!(state.committed_tip(), BlockNumber::GENESIS);
    assert_eq!(state.proven_tip(), BlockNumber::GENESIS);

    validator.reject_transaction.store(false, Ordering::SeqCst);
    Box::pin(deploy_fee_collector(
        &state,
        &mut writer,
        &mut proof_writer,
        account_file.clone(),
        validator_urls.clone(),
        Duration::from_secs(30),
    ))
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), BlockNumber::GENESIS.child());
    assert_eq!(state.proven_tip(), state.committed_tip());
    assert!(state.load_proof(state.proven_tip()).await.unwrap().is_some());
    assert!(collector_is_deployed(&state, &account).await.unwrap());
    assert_eq!(account.nonce(), ONE);
    assert!(account.vault().is_empty());
    assert_eq!(validator.transactions.lock().unwrap().len(), 1);
    validator.reject_transaction.store(true, Ordering::SeqCst);
    Box::pin(deploy_fee_collector(
        &state,
        &mut writer,
        &mut proof_writer,
        account_file,
        validator_urls.clone(),
        Duration::from_secs(30),
    ))
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), BlockNumber::GENESIS.child());
    assert_eq!(state.proven_tip(), state.committed_tip());
    assert_eq!(validator.transactions.lock().unwrap().len(), 1);
    validator.reject_transaction.store(false, Ordering::SeqCst);
    let replacement = mock_collection_account();
    assert_ne!(replacement.account().id(), account.id());
    Box::pin(deploy_fee_collector(
        &state,
        &mut writer,
        &mut proof_writer,
        replacement.clone(),
        validator_urls,
        Duration::from_secs(30),
    ))
    .await
    .unwrap();
    assert_eq!(state.committed_tip(), BlockNumber::GENESIS.child().child());
    assert_eq!(state.proven_tip(), state.committed_tip());
    assert!(state.load_proof(state.proven_tip()).await.unwrap().is_some());
    let (mut replacement, _) = replacement.into_parts();
    replacement.set_nonce(ONE).unwrap();
    assert!(collector_is_deployed(&state, &replacement).await.unwrap());
    assert!(collector_is_deployed(&state, &account).await.unwrap());
    assert_eq!(validator.transactions.lock().unwrap().len(), 2);

    shutdown.cancel();
    server.await.unwrap();
    writer.stop(writer_task).await;
}

fn genesis_with_faucet(signer: &SigningKey) -> GenesisBlock {
    let faucet = mock_native_faucet();
    let config = ProtocolConfig::current(AssetId::new_fungible(faucet.id())).unwrap();
    GenesisState::new(
        vec![faucet],
        FeeParameters::new(1),
        1,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        config,
    )
    .into_block()
    .unwrap()
}

/// Signs blocks only after it accepts their transactions and decrypts their execution inputs.
#[derive(Clone)]
struct Validator {
    signer: SigningKey,
    genesis: Word,
    encryption_secret: KeyExchangeKey,
    transactions: Arc<Mutex<BTreeSet<TransactionId>>>,
    reject_transaction: Arc<AtomicBool>,
}

impl Validator {
    async fn serve(self, shutdown: CancellationToken) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(validator_api::service(self))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    shutdown.cancelled_owned(),
                )
                .await
                .unwrap();
        });
        (format!("http://{address}").parse().unwrap(), server)
    }
}

#[tonic::async_trait]
impl validator_api::GetTransactionEncryptionKey for Validator {
    type Input = ();
    type Output = proto::submission::TransactionEncryptionKey;

    fn decode(input: ()) -> tonic::Result<Self::Input> {
        Ok(input)
    }

    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }

    async fn handle(
        &self,
        (): Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        let mut key = proto::submission::TransactionEncryptionKey {
            scheme: TransactionEncryptionScheme::X25519XChaCha20Poly1305.as_i32(),
            key_id: vec![1],
            public_key: self.encryption_secret.public_key().to_bytes(),
            attestations: vec![],
            next_key: None,
        };
        let info = TransactionEncryptionKeyInfo {
            scheme: TransactionEncryptionScheme::X25519XChaCha20Poly1305,
            key_id: key.key_id.clone(),
            public_key: key.public_key.clone(),
            next_key: None,
        };
        key.attestations.push(proto::submission::ValidatorKeyAttestation {
            validator_public_key: Some(self.signer.public_key().into()),
            signature: Some(self.signer.sign(info.attestation_commitment(self.genesis)).into()),
        });
        Ok(key)
    }
}

#[tonic::async_trait]
impl validator_api::SubmitProvenTransaction for Validator {
    type Input = proto::submission::ProvenTransactionSubmission;
    type Output = ();

    fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
        Ok(input)
    }

    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }

    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        if self.reject_transaction.load(Ordering::SeqCst) {
            return Err(tonic::Status::invalid_argument("transaction rejected"));
        }
        let submission = input.decode_fields().unwrap().build_unchecked().unwrap();
        let transaction = submission.transaction;
        let sealed = submission.sealed_transaction_inputs;
        let associated_data = transaction_inputs_associated_data(
            TransactionEncryptionScheme::X25519XChaCha20Poly1305.as_u32(),
            &sealed.key_id,
            self.genesis,
            transaction.id(),
        );
        let plaintext = UnsealingKey::X25519XChaCha20Poly1305(self.encryption_secret.clone())
            .unseal_bytes_with_associated_data(
                SealedMessage::read_from_bytes(&sealed.ciphertext).unwrap(),
                &associated_data,
            )
            .unwrap();
        let inputs = TransactionInputs::read_from_bytes(&plaintext).unwrap();
        assert!(inputs.account().is_new());
        assert_eq!(inputs.account().id(), transaction.account_id());
        assert!(transaction.input_notes().is_empty());
        assert!(transaction.output_notes().is_empty());
        // Batch proving settles any remaining precompile work.
        let _outcome =
            TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&transaction).unwrap();
        self.transactions.lock().unwrap().insert(transaction.id());
        Ok(())
    }
}

#[tonic::async_trait]
impl validator_api::SignBlock for Validator {
    type Input = proto::validator::SignBlockRequest;
    type Output = proto::validator::SignBlockResponse;

    fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
        Ok(input)
    }

    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }

    async fn handle(
        &self,
        input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        let proposal = input.decode_fields().unwrap().build_unchecked().unwrap();
        let transactions = self.transactions.lock().unwrap();
        let txs = proposal
            .tx_batches
            .as_slice()
            .iter()
            .flat_map(|batch| batch.transactions().as_slice());
        for tx in txs {
            assert!(transactions.contains(&tx.id()), "block contains an unvalidated transaction");
        }
        let commitment = proposal.block_header.commitment();
        Ok(proto::validator::SignBlockResponse {
            signature: Some(self.signer.sign(commitment).into()),
            block_commitment: Some(commitment.into()),
            public_key: Some(self.signer.public_key().into()),
        })
    }
}

#[tonic::async_trait]
impl validator_api::Status for Validator {
    type Input = ();
    type Output = proto::validator::ValidatorStatus;

    fn decode(input: ()) -> tonic::Result<Self::Input> {
        Ok(input)
    }

    fn encode(output: Self::Output) -> tonic::Result<Self::Output> {
        Ok(output)
    }

    async fn handle(
        &self,
        (): Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::Output> {
        Err(tonic::Status::unimplemented("unused"))
    }
}

#[tonic::async_trait]
impl validator_api::BlockSubscription for Validator {
    type Input = proto::validator::BlockSubscriptionRequest;
    type Item = proto::validator::BlockSubscriptionResponse;
    type ItemStream = tokio_stream::Empty<tonic::Result<Self::Item>>;

    fn decode(input: Self::Input) -> tonic::Result<Self::Input> {
        Ok(input)
    }

    fn encode(output: Self::Item) -> tonic::Result<Self::Item> {
        Ok(output)
    }

    async fn handle(
        &self,
        _input: Self::Input,
        _metadata: &MetadataMap,
        _extensions: &Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        Err(tonic::Status::unimplemented("unused"))
    }
}
