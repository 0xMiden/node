use miden_node_proto::generated::blockchain::BlockNumber;
use miden_node_proto::generated::miden::note_transport::v1::{
    FetchNotesCursor,
    FetchNotesRequest,
    FetchNotesResponse,
    FetchedNote,
    SendNoteWithProofRequest,
    SendNoteWithProofResponse,
    TransportNote,
};
use miden_node_proto::server::miden_note_transport_v1_note_transport_service::{
    FetchNotes,
    SendNoteWithProof,
};
use miden_node_proto::{BuildUnchecked, DecodeMessage};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteDetails,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_MAX_ZEROES;
use prost::Message;
use tonic::Request;

use super::*;

fn note(serial: u32, tag: u32) -> TransportNote {
    note_with_type(serial, tag, NoteType::Private)
}

fn note_with_type(serial: u32, tag: u32, note_type: NoteType) -> TransportNote {
    let recipient = NoteRecipient::new(
        Word::from([serial, 0, 0, 0]),
        NoteScript::mock(),
        NoteStorage::new(vec![]).unwrap(),
    );
    let metadata =
        PartialNoteMetadata::new(AccountId::try_from(ACCOUNT_ID_MAX_ZEROES).unwrap(), note_type)
            .with_tag(NoteTag::new(tag));
    let note = Note::new(NoteAssets::default(), metadata, recipient);
    TransportNote {
        header: Some((*note.header()).into()),
        details: Some(NoteDetails::from(note).into()),
    }
}

fn server(config: Config) -> (tempfile::TempDir, Server) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite3");
    db::bootstrap(&path).unwrap();
    let (writer, reader) = db::load(&path).unwrap();
    (dir, Server::new(config, writer, reader).unwrap())
}

fn fetched_note(note: TransportNote, block_num: u32) -> FetchedNote {
    FetchedNote {
        header: note.header,
        details: note.details,
        committed_in_block: Some(BlockNumber { block_num }),
    }
}

fn proof_request(server: &Server, note: TransportNote, block_num: u32) -> SendNoteWithProofRequest {
    let (request, response) = proofs::fixture_for_note(block_num, note);
    let header = response
        .block_header
        .unwrap()
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .unwrap();
    // Seed the trusted root for tests that do not exercise node lookups.
    server.note_root_cache.put(block_num.into(), header.note_root());
    request
}

fn invalid_note_request(note: Option<TransportNote>) -> SendNoteWithProofRequest {
    let (mut request, _) = proofs::fixture_for_note(42, self::note(1, 7));
    request.note = note;
    request
}

#[test]
fn fetched_note_requires_inclusion_block_on_the_wire() {
    let mut note = fetched_note(note(1, 7), 0);
    let decoded = FetchedNote::decode(note.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap();
    assert_eq!(decoded.committed_in_block.verify().unwrap().as_u32(), 0);
    note.committed_in_block = None;
    let error = FetchedNote::decode(note.encode_to_vec().as_slice())
        .unwrap()
        .decode_fields()
        .unwrap_err();
    assert!(error.to_string().starts_with("committed_in_block:"), "{error}");
}

#[tokio::test]
async fn send_fetch_preserves_inclusion_block() {
    let (_dir, server) = server(test_config());
    let cases = [0, 42, u32::MAX];
    let mut expected = Vec::new();
    for (serial, block_num) in cases.into_iter().enumerate() {
        let note = note(u32::try_from(serial).unwrap(), 7);
        SendNoteWithProof::full(
            &server,
            Request::new(proof_request(&server, note.clone(), block_num)),
        )
        .await
        .unwrap();
        expected.push(fetched_note(note, block_num));
    }
    let page = FetchNotes::full(
        &server,
        Request::new(FetchNotesRequest { tags: vec![8, 7, 7], cursor: None }),
    )
    .await
    .unwrap();
    assert_eq!(page.notes, expected);
    assert!(!page.has_more);
    assert!(page.cursor.unwrap().sequence > 0);
    let empty = FetchNotes::full(
        &server,
        Request::new(FetchNotesRequest { tags: vec![7, 8], cursor: page.cursor }),
    )
    .await
    .unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, page.cursor);
}

#[tokio::test]
async fn duplicate_send_preserves_first_note_and_cursor() {
    let (_dir, server) = server(test_config());
    let first = note(1, 7);
    let block_num = 100;
    SendNoteWithProof::full(
        &server,
        Request::new(proof_request(&server, first.clone(), block_num)),
    )
    .await
    .unwrap();
    let request = FetchNotesRequest { tags: vec![7], cursor: None };
    let before = FetchNotes::full(&server, Request::new(request.clone())).await.unwrap();

    // A retry preserves the first inclusion block.
    SendNoteWithProof::full(&server, Request::new(proof_request(&server, first.clone(), 101)))
        .await
        .unwrap();
    let after = FetchNotes::full(&server, Request::new(request)).await.unwrap();
    assert_eq!(after.notes, vec![fetched_note(first, block_num)]);
    assert_eq!(after.cursor, before.cursor);
    assert!(!after.has_more);
}

#[tokio::test]
async fn rejects_public_note_without_storage() {
    let (_dir, server) = server(test_config());
    let request = FetchNotesRequest { tags: vec![7], cursor: None };
    let before = FetchNotes::full(&server, Request::new(request.clone())).await.unwrap();
    let error = SendNoteWithProof::full(
        &server,
        Request::new(invalid_note_request(Some(note_with_type(1, 7, NoteType::Public)))),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "only private notes are supported");
    assert_eq!(FetchNotes::full(&server, Request::new(request)).await.unwrap(), before);
}

#[tokio::test]
async fn rejects_missing_note() {
    let (_dir, server) = server(test_config());
    let error = SendNoteWithProof::full(&server, Request::new(invalid_note_request(None)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn invalid_cursor_has_generic_message() {
    let (_dir, server) = server(test_config());
    let error = FetchNotes::full(
        &server,
        Request::new(FetchNotesRequest {
            tags: vec![7],
            cursor: Some(FetchNotesCursor { nonce: 0, sequence: u64::MAX }),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "invalid cursor");
    let error = storage_status(db::StorageError::InvalidCursor);
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "invalid cursor");
}

#[tokio::test]
async fn rejects_missing_or_mismatched_note_fields() {
    let (_dir, server) = server(test_config());
    let valid = note(1, 7);
    let mut no_header = valid.clone();
    no_header.header = None;
    let mut no_details = valid.clone();
    no_details.details = None;
    let mut mismatch = valid;
    mismatch.details = note(2, 7).details;
    for note in [TransportNote::default(), no_header, no_details, mismatch] {
        let error =
            SendNoteWithProof::full(&server, Request::new(invalid_note_request(Some(note))))
                .await
                .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}

#[tokio::test]
async fn rejects_malformed_nested_note_fields() {
    let (_dir, server) = server(test_config());
    let mut note = note(1, 7);
    note.details.as_mut().unwrap().recipient = None;
    let error = SendNoteWithProof::full(&server, Request::new(invalid_note_request(Some(note))))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn rejects_invalid_note_metadata() {
    let (_dir, server) = server(test_config());
    let mut note = note(1, 7);
    note.header.as_mut().unwrap().metadata.as_mut().unwrap().note_type =
        miden_node_proto::generated::note::NoteType::Unspecified.into();
    let error = SendNoteWithProof::full(&server, Request::new(invalid_note_request(Some(note))))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn rejects_oversized_notes_and_invalid_fetches() {
    let (_dir, server) = server(Config {
        max_note_size: NonZeroUsize::new(1).unwrap(),
        ..test_config()
    });
    let error =
        SendNoteWithProof::full(&server, Request::new(proof_request(&server, note(1, 7), 42)))
            .await
            .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    for request in [
        FetchNotesRequest { tags: vec![7; 129], cursor: None },
        FetchNotesRequest {
            tags: vec![],
            cursor: Some(FetchNotesCursor { nonce: 0, sequence: u64::MAX }),
        },
    ] {
        let error = FetchNotes::full(&server, Request::new(request)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}

#[tokio::test]
async fn capacity_failure_does_not_store_the_note() {
    let (_dir, server) = server(Config {
        max_storage_bytes: NonZeroU64::new(1).unwrap(),
        ..test_config()
    });
    let error =
        SendNoteWithProof::full(&server, Request::new(proof_request(&server, note(1, 7), 42)))
            .await
            .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let page =
        FetchNotes::full(&server, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
            .await
            .unwrap();
    assert!(page.notes.is_empty());
}

async fn grpc_web_request(
    address: std::net::SocketAddr,
    method: &str,
    request: impl prost::Message,
) -> reqwest::Response {
    let request = request.encode_to_vec();
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(request.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&request);
    reqwest::Client::new()
        .post(format!(
            "http://{address}/miden.note_transport.v1.NoteTransportService/{method}"
        ))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .header("origin", "https://wallet.example")
        .body(frame)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn grpc_health_reflection_web_and_shutdown() {
    use miden_node_proto::generated::miden::note_transport::v1::note_transport_service_client::NoteTransportServiceClient;
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::health_client::HealthClient;

    let (_dir, server) = server(test_config());
    let envelope = note(1, 123);
    let request = proof_request(&server, envelope.clone(), 0);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut health = HealthClient::new(channel.clone());
    let health_response = health
        .check(HealthCheckRequest {
            service: miden_node_proto::server::miden_note_transport_v1_note_transport_service::service_name().into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health_response.status, ServingStatus::Serving as i32);

    let mut client = NoteTransportServiceClient::new(channel.clone());
    client.send_note_with_proof(request.clone()).await.unwrap();
    let response = client
        .fetch_notes(FetchNotesRequest { tags: vec![123], cursor: None })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.notes, vec![fetched_note(envelope.clone(), 0)]);
    let error = client
        .send_note_with_proof(SendNoteWithProofRequest::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);

    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready().await.unwrap();
    let error = grpc
        .unary(
            Request::new(SendNoteWithProofRequest::default()),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/miden.note_transport.v1.NoteTransportService/SendNote",
            ),
            tonic_prost::ProstCodec::<SendNoteWithProofRequest, SendNoteWithProofResponse>::default(
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    drop(grpc);

    check_reflection(channel).await;
    drop(client);
    drop(health);

    check_grpc_web(address, request, response).await;
    let removed = grpc_web_request(address, "SendNote", SendNoteWithProofRequest::default()).await;
    let headers = removed.headers().clone();
    let body = removed.bytes().await.unwrap();
    assert!(
        headers.get("grpc-status").is_some_and(|status| status == "12")
            || String::from_utf8_lossy(&body).contains("grpc-status:12"),
        "expected UNIMPLEMENTED, got {headers:?}, {body:?}"
    );

    shutdown.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn check_reflection(channel: tonic::transport::Channel) {
    use tonic_reflection::pb::v1::ServerReflectionRequest;
    use tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient;
    use tonic_reflection::pb::v1::server_reflection_request::MessageRequest;
    use tonic_reflection::pb::v1::server_reflection_response::MessageResponse;

    let mut reflection = ServerReflectionClient::new(channel);
    let mut stream = reflection
        .server_reflection_info(tokio_stream::iter([ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        }]))
        .await
        .unwrap()
        .into_inner();
    let reflected = stream.message().await.unwrap().unwrap();
    let Some(MessageResponse::ListServicesResponse(services)) = reflected.message_response else {
        panic!("expected reflected services");
    };
    assert!(
        services
            .service
            .iter()
            .any(|service| service.name == "miden.note_transport.v1.NoteTransportService")
    );
    drop(stream);
    let mut stream = reflection
        .server_reflection_info(tokio_stream::iter([ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::FileContainingSymbol(
                "miden.note_transport.v1.NoteTransportService".into(),
            )),
        }]))
        .await
        .unwrap()
        .into_inner();
    let reflected = stream.message().await.unwrap().unwrap();
    let Some(MessageResponse::FileDescriptorResponse(files)) = reflected.message_response else {
        panic!("expected reflected descriptors");
    };
    let methods: Vec<_> = files
        .file_descriptor_proto
        .iter()
        .map(|bytes| prost_types::FileDescriptorProto::decode(bytes.as_slice()).unwrap())
        .filter(|file| file.package() == "miden.note_transport.v1")
        .flat_map(|file| file.service)
        .filter(|service| service.name() == "NoteTransportService")
        .flat_map(|service| service.method)
        .map(|method| method.name.unwrap())
        .collect();
    assert_eq!(methods, ["SendNoteWithProof", "FetchNotes"]);
    drop(stream);
    drop(reflection);
}

async fn check_grpc_web(
    address: std::net::SocketAddr,
    request: SendNoteWithProofRequest,
    response: FetchNotesResponse,
) {
    let web = grpc_web_request(address, "SendNoteWithProof", request).await;
    assert_eq!(web.status(), reqwest::StatusCode::OK);
    let frame = web.bytes().await.unwrap();
    assert_eq!(frame[0], 0);
    let length = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
    assert_eq!(
        SendNoteWithProofResponse::decode(&frame[5..5 + length]).unwrap(),
        SendNoteWithProofResponse {}
    );

    let web = grpc_web_request(
        address,
        "FetchNotes",
        FetchNotesRequest { tags: vec![123], cursor: None },
    )
    .await;
    assert_eq!(web.status(), reqwest::StatusCode::OK);
    assert_eq!(web.headers()["access-control-allow-origin"], "*");
    let frame = web.bytes().await.unwrap();
    assert_eq!(frame[0], 0);
    let length = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
    let page = FetchNotesResponse::decode(&frame[5..5 + length]).unwrap();
    assert_eq!(page.notes.len(), 1);
    assert_eq!(page, response);
}

#[tokio::test]
async fn large_pages_fit_default_grpc_client_and_resume_without_gaps() {
    let (_dir, server) = server(test_config());
    for serial in 1_u32..=400 {
        let recipient = NoteRecipient::new(
            Word::from([serial, 0, 0, 0]),
            NoteScript::mock(),
            NoteStorage::new(vec![miden_protocol::Felt::from(1_u32); 1024]).unwrap(),
        );
        let metadata = PartialNoteMetadata::new(
            AccountId::try_from(ACCOUNT_ID_MAX_ZEROES).unwrap(),
            NoteType::Private,
        )
        .with_tag(NoteTag::new(77));
        let note = Note::new(NoteAssets::default(), metadata, recipient);
        SendNoteWithProof::full(
            &server,
            Request::new(proof_request(
                &server,
                TransportNote {
                    header: Some((*note.header()).into()),
                    details: Some(NoteDetails::from(note).into()),
                },
                serial,
            )),
        )
        .await
        .unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let mut client = miden_node_proto::generated::miden::note_transport::v1::note_transport_service_client::NoteTransportServiceClient::connect(
        format!("http://{address}"),
    )
    .await
    .unwrap();
    let first = client
        .fetch_notes(FetchNotesRequest { tags: vec![77], cursor: None })
        .await
        .unwrap()
        .into_inner();
    assert!(first.has_more);
    assert!(!first.notes.is_empty());
    let second = client
        .fetch_notes(FetchNotesRequest { tags: vec![77], cursor: first.cursor })
        .await
        .unwrap()
        .into_inner();
    assert!(!second.has_more);
    assert_eq!(first.notes.len() + second.notes.len(), 400);
    let headers = first
        .notes
        .iter()
        .chain(&second.notes)
        .map(|note| {
            let header = note.header.clone().unwrap().decode_fields().unwrap().verify().unwrap();
            header.id()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(headers.len(), 400);
    drop(client);
    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn rejects_cursor_from_another_database() {
    let (_first_dir, first) = server(test_config());
    let (_second_dir, second) = server(test_config());
    let page =
        FetchNotes::full(&first, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
            .await
            .unwrap();
    for tags in [vec![7], vec![]] {
        let error = FetchNotes::full(
            &second,
            Request::new(FetchNotesRequest { tags, cursor: page.cursor }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }
}

#[tokio::test]
async fn cursor_survives_reopening_database() {
    let (dir, server) = server(test_config());
    SendNoteWithProof::full(&server, Request::new(proof_request(&server, note(1, 7), 42)))
        .await
        .unwrap();
    let first =
        FetchNotes::full(&server, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
            .await
            .unwrap();
    drop(server);
    let path = dir.path().join("notes.sqlite3");
    db::migrate(&path).unwrap();
    let (writer, reader) = db::load(&path).unwrap();
    let server = Server::new(test_config(), writer, reader).unwrap();
    let empty = FetchNotes::full(
        &server,
        Request::new(FetchNotesRequest { tags: vec![7], cursor: first.cursor }),
    )
    .await
    .unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, first.cursor);
    let next = note(2, 7);
    SendNoteWithProof::full(&server, Request::new(proof_request(&server, next.clone(), 42)))
        .await
        .unwrap();
    let page = FetchNotes::full(
        &server,
        Request::new(FetchNotesRequest { tags: vec![7], cursor: empty.cursor }),
    )
    .await
    .unwrap();
    assert_eq!(page.notes, vec![fetched_note(next, 42)]);
}

#[tokio::test]
async fn stale_cursor_fails_before_and_after_sequence_catches_up() {
    let (_first_dir, first) = server(test_config());
    let (_second_dir, second) = server(test_config());
    SendNoteWithProof::full(&first, Request::new(proof_request(&first, note(1, 7), 42)))
        .await
        .unwrap();
    let previous =
        FetchNotes::full(&first, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
            .await
            .unwrap();
    for count in 0..=2 {
        if count > 0 {
            SendNoteWithProof::full(
                &second,
                Request::new(proof_request(&second, note(count, 7), 42)),
            )
            .await
            .unwrap();
        }
        let error = FetchNotes::full(
            &second,
            Request::new(FetchNotesRequest { tags: vec![7], cursor: previous.cursor }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }
    let restarted =
        FetchNotes::full(&second, Request::new(FetchNotesRequest { tags: vec![7], cursor: None }))
            .await
            .unwrap();
    assert_eq!(
        restarted.notes,
        vec![fetched_note(note(1, 7), 42), fetched_note(note(2, 7), 42)]
    );
    assert_eq!(restarted.cursor.unwrap().sequence, 2);
}

#[tokio::test]
async fn empty_pages_and_nonce_extremes_roundtrip() {
    let (_dir, server) = server(test_config());
    for nonce in [0, u64::MAX] {
        server
            .writer
            .write("set database nonce", move |tx| {
                tx.execute(
                    "UPDATE storage_metadata SET nonce = ?1",
                    &[&nonce.to_le_bytes().to_vec()],
                )?;
                Ok::<_, db::StorageError>(())
            })
            .await
            .unwrap();
        for tags in [vec![7], vec![]] {
            let initial = FetchNotes::full(
                &server,
                Request::new(FetchNotesRequest { tags: tags.clone(), cursor: None }),
            )
            .await
            .unwrap();
            assert!(initial.notes.is_empty());
            assert!(!initial.has_more);
            assert_eq!(initial.cursor, Some(FetchNotesCursor { nonce, sequence: 0 }));
            let response = FetchNotesResponse::decode(initial.encode_to_vec().as_slice()).unwrap();
            let request = FetchNotesRequest {
                tags: tags.clone(),
                cursor: response.cursor,
            };
            let request = FetchNotesRequest::decode(request.encode_to_vec().as_slice()).unwrap();
            let next = FetchNotes::full(&server, Request::new(request)).await.unwrap();
            assert_eq!(next.cursor, initial.cursor);
            assert!(next.notes.is_empty());
            let error = FetchNotes::full(
                &server,
                Request::new(FetchNotesRequest {
                    tags,
                    cursor: Some(FetchNotesCursor { nonce: nonce ^ 1, sequence: 0 }),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }
    }
}

#[tokio::test]
async fn missing_metadata_fails_even_without_tags() {
    let (_dir, server) = server(test_config());
    server
        .writer
        .write("remove metadata", |tx| {
            tx.execute("DELETE FROM storage_metadata", &[])?;
            Ok::<_, db::StorageError>(())
        })
        .await
        .unwrap();
    let error =
        FetchNotes::full(&server, Request::new(FetchNotesRequest { tags: vec![], cursor: None }))
            .await
            .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn proof_submission_requires_a_proof_over_grpc_web() {
    let (_dir, server) = server(test_config());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve_on(listener, shutdown.clone()));
    let response = grpc_web_request(
        address,
        "SendNoteWithProof",
        SendNoteWithProofRequest {
            note: Some(note(1, 7)),
            inclusion_proof: None,
        },
    )
    .await;
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap();
    shutdown.cancel();
    task.await.unwrap().unwrap();
    assert!(
        headers.get("grpc-status").is_some_and(|status| status == "3")
            || String::from_utf8_lossy(&body).contains("grpc-status:3"),
        "expected INVALID_ARGUMENT, got {headers:?}, {body:?}"
    );
}

mod proofs;

fn test_config() -> Config {
    Config::new("http://127.0.0.1:1".parse().unwrap())
}
