//     use std::time::Duration;

//     use miden_node_utils::cors::cors_for_grpc_web_layer;
//     use miden_protocol::asset::{Asset, FungibleAsset};
//     use miden_protocol::note::NoteType;
//     use miden_protocol::testing::account_id::{
//         ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
//         ACCOUNT_ID_SENDER,
//     };
//     use miden_protocol::transaction::ProvenTransaction;
//     use miden_testing::{Auth, MockChainBuilder};
//     use miden_tx::utils::Serializable;
//     use tokio::net::TcpListener;
//     use tonic::Request;
//     use tonic_web::GrpcWebLayer;

//     use crate::generated::api_client::ApiClient;
//     use crate::generated::api_server::ApiServer;
//     use crate::generated::{self as proto};
//     use crate::server::prover::ProverRpcApi;

//     #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
//     async fn test_prove_transaction() {
//         // Start the server in the background
//         let listener = TcpListener::bind("127.0.0.1:50052").await.unwrap();

//         let proof_type = proto::remote_prover::ProofType::Transaction;

//         let api_service = ApiServer::new(ProverRpcApi::new(proof_type.into()));

//         // Spawn the server as a background task
//         tokio::spawn(async move {
//             tonic::transport::Server::builder()
//                 .accept_http1(true)
//                 .layer(cors_for_grpc_web_layer())
//                 .layer(GrpcWebLayer::new())
//                 .add_service(api_service)
//                 .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
//                 .await
//                 .unwrap();
//         });

//         // Give the server some time to start
//         tokio::time::sleep(Duration::from_secs(1)).await;

//         // Set up a gRPC client to send the request
//         let mut client = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();
//         let mut client_2 = ApiClient::connect("http://127.0.0.1:50052").await.unwrap();

//         // Create a mock transaction to send to the server
//         let mut mock_chain_builder = MockChainBuilder::new();
//         let account = mock_chain_builder.add_existing_wallet(Auth::BasicAuth).unwrap();

//         let fungible_asset_1: Asset =
//             FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap(), 100)
//                 .unwrap()
//                 .into();
//         let note_1 = mock_chain_builder
//             .add_p2id_note(
//                 ACCOUNT_ID_SENDER.try_into().unwrap(),
//                 account.id(),
//                 &[fungible_asset_1],
//                 NoteType::Private,
//             )
//             .unwrap();

//         let mock_chain = mock_chain_builder.build().unwrap();

//         let tx_context = mock_chain
//             .build_tx_context(account.id(), &[note_1.id()], &[])
//             .unwrap()
//             .build()
//             .unwrap();

//         let executed_transaction = Box::pin(tx_context.execute()).await.unwrap();
//         let tx_inputs = executed_transaction.tx_inputs();

//         let request_1 = Request::new(proto::remote_prover::ProofRequest {
//             proof_type: proto::remote_prover::ProofType::Transaction.into(),
//             payload: tx_inputs.to_bytes(),
//         });

//         let request_2 = Request::new(proto::remote_prover::ProofRequest {
//             proof_type: proto::remote_prover::ProofType::Transaction.into(),
//             payload: tx_inputs.to_bytes(),
//         });

//         // Send both requests concurrently
//         let (response_1, response_2) =
//             tokio::join!(client.prove(request_1), client_2.prove(request_2));

//         // Check the success response
//         assert!(response_1.is_ok() || .is_ok());

//         // Check the failure response
//         assert!(response_1.is_err() || response_2.is_err());

//         let response_success = response_1.or(response_2).unwrap();

//         // Cast into a ProvenTransaction
//         let _proven_transaction: ProvenTransaction =
//             response_success.into_inner().try_into().expect("Failed to convert response");
//     }

// Create test for
// - capacity=1 to ensure legacy behaviour works as expected
// - capacity=2 to test concurrency is allowed
// - invalid kind=100 is rejected
// - unsupported kind is rejected
// - timeout is respected
// - transaction proof succeeds
// - batch proof succeeds
// - block proof succeeds
