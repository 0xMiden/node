use std::collections::BTreeMap;

use miden_node_proto::clients::Builder;
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::{BlockSubscriptionResponse, RpcStatus};
use miden_node_proto::generated::server::rpc_api;
use miden_node_store::GenesisState;
use miden_node_utils::clap::StorageOptions;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::block::{
    BlockHeader,
    BlockInputs,
    BlockSignatures,
    ProposedBlock,
    SignedBlock,
    ValidatorConfig,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::transaction::PartialBlockchain;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;

use super::*;

#[derive(Clone)]
struct Upstream(Vec<SignedBlock>);

#[tonic::async_trait]
impl rpc_api::Status for Upstream {
    type Input = ();
    type Output = RpcStatus;

    fn decode(request: ()) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(output: Self::Output) -> tonic::Result<RpcStatus> {
        Ok(output)
    }

    async fn handle(
        &self,
        (): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        Ok(RpcStatus {
            chain_tip: self.0.last().unwrap().header().block_num().as_u32(),
            ..Default::default()
        })
    }
}

#[tonic::async_trait]
impl rpc_api::BlockSubscription for Upstream {
    type Input = BlockSubscriptionRequest;
    type Item = BlockSubscriptionResponse;
    type ItemStream = tokio_stream::Iter<std::vec::IntoIter<tonic::Result<Self::Item>>>;

    fn decode(request: BlockSubscriptionRequest) -> tonic::Result<Self::Input> {
        Ok(request)
    }

    fn encode(item: Self::Item) -> tonic::Result<BlockSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(
        &self,
        request: Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        let committed_chain_tip = self.0.last().unwrap().header().block_num().as_u32();
        let events = self
            .0
            .iter()
            .filter(|block| block.header().block_num().as_u32() >= request.block_from)
            .map(|block| {
                Ok(BlockSubscriptionResponse {
                    block: Some(block.into()),
                    committed_chain_tip,
                })
            })
            .collect::<Vec<_>>();
        Ok(tokio_stream::iter(events))
    }
}

async fn sync_blocks(
    genesis: &GenesisState,
    blocks: Vec<SignedBlock>,
) -> (anyhow::Result<()>, BlockHeader) {
    let directory = tempfile::tempdir().unwrap();
    State::bootstrap(genesis.clone().into_block().unwrap(), directory.path()).unwrap();
    let (state, writer, _proof_writer, writer_task) =
        State::load(directory.path(), StorageOptions::default())
            .await
            .unwrap()
            .start(CancellationToken::new());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(rpc_api::service(Upstream(blocks)))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_shutdown.cancelled_owned(),
            )
            .await
            .unwrap();
    });
    let source_rpc = Builder::new(format!("http://{address}").parse().unwrap())
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect_lazy::<RpcClient>();
    let (reporter, _) = tonic_health::server::health_reporter();
    let mut sync = BlockSync {
        state: Arc::clone(&state),
        writer,
        source_rpc,
        readiness: RpcReadiness::new(reporter, 0),
    };
    let result = tokio::time::timeout(Duration::from_secs(10), sync.sync(shutdown.clone()))
        .await
        .expect("block sync should finish");
    let (tip, _) = state.view().get_block_header(None, false).await.unwrap();

    shutdown.cancel();
    server.await.unwrap();
    sync.writer.stop(writer_task).await;
    (result, tip.unwrap())
}

fn genesis(signer: &SigningKey) -> GenesisState {
    GenesisState::new(
        vec![],
        test_fee_params(),
        0,
        ValidatorConfig::new(vec![signer.public_key()], 1).unwrap(),
        test_protocol_config(),
    )
}

fn child(
    parent: &BlockHeader,
    chain: PartialBlockchain,
    signer: &SigningKey,
    next_signer: &SigningKey,
) -> SignedBlock {
    let inputs =
        BlockInputs::new(parent.clone(), chain, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let (header, body) = ProposedBlock::new_at(inputs, vec![], parent.timestamp() + 1)
        .unwrap()
        .with_next_validator_config(
            ValidatorConfig::new(vec![next_signer.public_key()], 1).unwrap(),
        )
        .into_header_and_body()
        .unwrap();
    let signatures = BlockSignatures::new(vec![signer.sign(header.commitment())]).unwrap();
    SignedBlock::new_unchecked(header, body, signatures)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synced_blocks_require_parent_signatures() {
    let signer = SigningKey::new();
    let attacker = SigningKey::new();
    let genesis = genesis(&signer);
    let parent = genesis.clone().into_block().unwrap().inner().header().clone();
    let forged = child(&parent, PartialBlockchain::default(), &attacker, &attacker);
    forged.validate(None).unwrap();
    let (header, body, _) = forged.clone().into_parts();
    let unsigned = SignedBlock::new_unchecked(header, body, BlockSignatures::new(vec![]).unwrap());

    for invalid in [forged, unsigned] {
        let (result, tip) = sync_blocks(&genesis, vec![invalid]).await;
        assert!(result.unwrap_err().to_string().contains("failed to verify block"));
        assert_eq!(tip, parent);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synced_blocks_follow_validator_rotation() {
    let signer = SigningKey::new();
    let next_signer = SigningKey::new();
    let genesis = genesis(&signer);
    let parent = genesis.clone().into_block().unwrap().inner().header().clone();
    let first = child(&parent, PartialBlockchain::default(), &signer, &next_signer);

    let mut chain = PartialBlockchain::default();
    chain.add_block(&parent, true);
    let second = child(first.header(), chain.clone(), &next_signer, &next_signer);
    let (result, tip) = sync_blocks(&genesis, vec![first.clone(), second.clone()]).await;
    result.unwrap();
    assert_eq!(&tip, second.header());

    let stale_signer = child(first.header(), chain, &signer, &signer);
    let (result, tip) = sync_blocks(&genesis, vec![first.clone(), stale_signer]).await;
    assert!(result.unwrap_err().to_string().contains("failed to verify block"));
    assert_eq!(&tip, first.header());
}

// The upstream fixture serves only status and block subscriptions.
macro_rules! unused_rpc {
    ($method:ident, $request:ty, $response:ty) => {
        #[tonic::async_trait]
        impl rpc_api::$method for Upstream {
            type Input = ();
            type Output = $response;

            fn decode(_request: $request) -> tonic::Result<Self::Input> {
                Err(tonic::Status::unimplemented("unused test endpoint"))
            }

            fn encode(output: Self::Output) -> tonic::Result<$response> {
                Ok(output)
            }

            async fn handle(
                &self,
                (): Self::Input,
                _metadata: &tonic::metadata::MetadataMap,
                _extensions: &tonic::codegen::http::Extensions,
            ) -> tonic::Result<Self::Output> {
                Err(tonic::Status::unimplemented("unused test endpoint"))
            }
        }
    };
}

unused_rpc!(GetLimits, (), proto::rpc::RpcLimits);
unused_rpc!(GetAccount, proto::rpc::AccountRequest, proto::rpc::AccountResponse);
unused_rpc!(GetBlockByNumber, proto::rpc::BlockRequest, proto::rpc::MaybeBlock);
unused_rpc!(
    GetBlockHeaderByNumber,
    proto::rpc::BlockHeaderByNumberRequest,
    proto::rpc::BlockHeaderByNumberResponse
);
unused_rpc!(GetNotesById, proto::rpc::NotesByIdRequest, proto::rpc::NotesByIdResponse);
unused_rpc!(
    GetNoteScriptByRoot,
    proto::rpc::NoteScriptByRootRequest,
    proto::rpc::MaybeNoteScript
);
unused_rpc!(GetTransactionEncryptionKey, (), proto::submission::TransactionEncryptionKey);
unused_rpc!(
    SubmitProvenTx,
    proto::submission::ProvenTransactionSubmission,
    proto::blockchain::BlockNumber
);
unused_rpc!(
    SubmitProvenTxBatch,
    proto::submission::TransactionBatch,
    proto::blockchain::BlockNumber
);
unused_rpc!(
    SyncTransactions,
    proto::rpc::SyncTransactionsRequest,
    proto::rpc::SyncTransactionsResponse
);
unused_rpc!(SyncNotes, proto::rpc::SyncNotesRequest, proto::rpc::SyncNotesResponse);
unused_rpc!(
    SyncNullifiers,
    proto::rpc::SyncNullifiersRequest,
    proto::rpc::SyncNullifiersResponse
);
unused_rpc!(
    SyncAccountVault,
    proto::rpc::SyncAccountVaultRequest,
    proto::rpc::SyncAccountVaultResponse
);
unused_rpc!(
    SyncAccountStorageMaps,
    proto::rpc::SyncAccountStorageMapsRequest,
    proto::rpc::SyncAccountStorageMapsResponse
);
unused_rpc!(SyncChainMmr, proto::rpc::SyncChainMmrRequest, proto::rpc::SyncChainMmrResponse);
unused_rpc!(
    GetNetworkNoteStatus,
    proto::note::NoteId,
    proto::rpc::GetNetworkNoteStatusResponse
);

#[tonic::async_trait]
impl rpc_api::ProofSubscription for Upstream {
    type Input = ();
    type Item = proto::rpc::ProofSubscriptionResponse;
    type ItemStream = tokio_stream::Empty<tonic::Result<Self::Item>>;

    fn decode(_request: proto::rpc::ProofSubscriptionRequest) -> tonic::Result<Self::Input> {
        Err(tonic::Status::unimplemented("unused test endpoint"))
    }

    fn encode(item: Self::Item) -> tonic::Result<proto::rpc::ProofSubscriptionResponse> {
        Ok(item)
    }

    async fn handle(
        &self,
        (): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::ItemStream> {
        Err(tonic::Status::unimplemented("unused test endpoint"))
    }
}
