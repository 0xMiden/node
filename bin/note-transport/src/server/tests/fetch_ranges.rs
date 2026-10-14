use super::*;

pub(super) async fn insert(server: &Server, serial: u32, tag: u32) -> FetchedNote {
    let envelope = note(serial, tag);
    let (header, details) = decode_note(envelope.clone().decode_fields().unwrap()).unwrap();
    server
        .store_note(db::NewNote {
            header,
            details,
            committed_in_block: miden_protocol::block::BlockNumber::from(42),
        })
        .await
        .unwrap();
    fetched_note(envelope, 42)
}

pub(super) async fn fetch(
    server: &Server,
    tags: Vec<u32>,
    cursor: Option<FetchNotesCursor>,
    sync_to: Option<FetchNotesCursor>,
) -> tonic::Result<FetchNotesResponse> {
    FetchNotes::full(server, Request::new(FetchNotesRequest { tags, cursor, sync_to })).await
}

#[tokio::test]
async fn returns_target_without_changing_page_cursor_semantics() {
    let (_dir, server) = server(test_config());
    let wanted = insert(&server, 1, 7).await;
    insert(&server, 2, 8).await;
    let page = fetch(&server, vec![7], None, None).await.unwrap();
    assert_eq!(page.notes, vec![wanted]);
    assert_eq!(page.cursor.unwrap().sequence, 1);
    let target = page.sync_to.unwrap();
    assert_eq!(target.sequence, 2);
    assert_eq!(target.nonce, page.cursor.unwrap().nonce);
    assert!(!page.has_more);
    let empty = fetch(&server, vec![99], page.cursor, Some(target)).await.unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, page.cursor);
    assert_eq!(empty.sync_to, Some(target));
    assert!(!empty.has_more);
}

#[tokio::test]
async fn empty_ranges_and_nonce_extremes_return_explicit_targets() {
    let (_dir, server) = server(test_config());
    for nonce in [0, u64::MAX] {
        server
            .writer
            .write("set nonce boundary", move |tx| {
                tx.execute(
                    "UPDATE storage_metadata SET nonce = ?1",
                    &[&nonce.to_le_bytes().to_vec()],
                )?;
                Ok::<_, db::StorageError>(())
            })
            .await
            .unwrap();
        let zero = FetchNotesCursor { nonce, sequence: 0 };
        for tags in [vec![], vec![7]] {
            let page = fetch(&server, tags.clone(), None, None).await.unwrap();
            assert_eq!(page.cursor, Some(zero));
            assert_eq!(page.sync_to, Some(zero));
            assert!(page.notes.is_empty());
            assert!(!page.has_more);
            let equal = fetch(&server, tags, Some(zero), Some(zero)).await.unwrap();
            assert_eq!(equal, page);
            let decoded = FetchNotesResponse::decode(page.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, page);
        }
    }
}

#[tokio::test]
async fn rejects_stale_upper_bound_without_a_lower_cursor() {
    let (_first_dir, first) = server(test_config());
    let (_second_dir, second) = server(test_config());
    // Choose two generations deterministically rather than relying on random inequality.
    for (instance, nonce) in [(&first, 10_u64), (&second, 11_u64)] {
        instance
            .writer
            .write("set test generation", move |tx| {
                tx.execute(
                    "UPDATE storage_metadata SET nonce = ?1",
                    &[&nonce.to_le_bytes().to_vec()],
                )?;
                Ok::<_, db::StorageError>(())
            })
            .await
            .unwrap();
        insert(instance, 1, 7).await;
    }
    let old = fetch(&first, vec![], None, None).await.unwrap().sync_to.unwrap();
    let new = fetch(&second, vec![], None, None).await.unwrap().sync_to.unwrap();
    for tags in [vec![], vec![7]] {
        for (lower, upper) in [(None, Some(old)), (Some(new), Some(old)), (Some(old), Some(new))] {
            let error = fetch(&second, tags.clone(), lower, upper).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }
    }
    let stale_future = FetchNotesCursor { sequence: 2, ..old };
    let error = fetch(&second, vec![], None, Some(stale_future)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn rejects_malformed_and_future_ranges() {
    let (_dir, server) = server(test_config());
    insert(&server, 1, 7).await;
    let head = fetch(&server, vec![], None, None).await.unwrap().sync_to.unwrap();
    let zero = FetchNotesCursor { sequence: 0, ..head };
    let future = FetchNotesCursor { sequence: 2, ..head };
    let overflow = FetchNotesCursor { sequence: u64::MAX, ..head };
    for (lower, upper, message) in [
        (None, Some(overflow), "invalid sync range"),
        (Some(overflow), None, "invalid cursor"),
        (Some(head), Some(zero), "invalid sync range"),
        (None, Some(future), "invalid sync range"),
        (Some(future), None, "invalid sync range"),
    ] {
        let error = fetch(&server, vec![], lower, upper).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.message(), message);
    }
    let error = fetch(&server, vec![7; 129], None, Some(head)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    let equal = fetch(&server, vec![7], Some(head), Some(head)).await.unwrap();
    assert!(equal.notes.is_empty());
    assert_eq!(equal.cursor, Some(head));
    assert_eq!(equal.sync_to, Some(head));
    assert!(!equal.has_more);
}

#[tokio::test]
async fn encoded_limit_preserves_target_and_withheld_note() {
    let (_dir, server) = server(test_config());
    let one = insert(&server, 1, 7).await;
    let two = insert(&server, 2, 7).await;
    let page = db::fetch_notes(&server.reader, vec![7], None, None).await.unwrap();
    let target = FetchNotesCursor {
        nonce: page.sync_to.nonce,
        sequence: page.sync_to.sequence,
    };
    let prefix = FetchNotesResponse {
        notes: vec![one.clone()],
        cursor: Some(FetchNotesCursor { sequence: 1, ..target }),
        has_more: true,
        sync_to: Some(target),
    };
    let limit = prefix.encoded_len();
    let first = super::super::fetch_notes::encode_page(page, None, limit).unwrap();
    assert_eq!(first, prefix);
    assert!(first.encoded_len() <= limit);
    let tail = fetch(&server, vec![7], first.cursor, first.sync_to).await.unwrap();
    assert_eq!(tail.notes, vec![two]);
    assert_eq!(tail.sync_to, Some(target));
    assert!(!tail.has_more);
    let page = db::fetch_notes(&server.reader, vec![7], None, None).await.unwrap();
    let error = super::super::fetch_notes::encode_page(page, None, limit - 1).unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn missing_metadata_fails_with_an_upper_bound() {
    let (_dir, server) = server(test_config());
    let bound = fetch(&server, vec![], None, None).await.unwrap().sync_to;
    server
        .writer
        .write("remove metadata", |tx| {
            tx.execute("DELETE FROM storage_metadata", &[])?;
            Ok::<_, db::StorageError>(())
        })
        .await
        .unwrap();
    let error = fetch(&server, vec![], None, bound).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Internal);
    assert_eq!(error.message(), "note storage operation failed");
}
