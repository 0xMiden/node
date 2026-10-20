use super::*;

#[tokio::test]
async fn fixed_range_has_independent_target_and_continuation() {
    let (_dir, writer, reader) = database();
    for (seed, tag) in [(1, 7), (2, 8), (3, 7), (4, 8)] {
        store_note(&writer, note(seed, tag), u64::MAX).await.unwrap();
    }
    let initial = fetch_notes(&reader, vec![7], None, None).await.unwrap();
    assert_eq!(initial.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![1, 3]);
    assert_eq!(initial.cursor.sequence, 3);
    assert_eq!(initial.sync_to.sequence, 4);
    assert!(!initial.has_more);
    let lower = Cursor { sequence: 1, ..initial.cursor };
    let upper = Cursor { sequence: 3, ..initial.sync_to };
    let page = fetch_notes(&reader, vec![7, 7, 8], Some(lower), Some(upper)).await.unwrap();
    assert_eq!(page.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(page.sync_to, upper);
    assert!(!page.has_more);
    let empty = fetch_notes(&reader, vec![99], Some(lower), Some(upper)).await.unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, lower);
    assert_eq!(empty.sync_to, upper);
    assert!(!empty.has_more);
    let equal = fetch_notes(&reader, vec![], Some(upper), Some(upper)).await.unwrap();
    assert!(equal.notes.is_empty());
    assert_eq!(equal.cursor, upper);
    assert_eq!(equal.sync_to, upper);
    assert!(!equal.has_more);
    let zero = Cursor { sequence: 0, ..upper };
    let empty = fetch_notes(&reader, vec![7], None, Some(zero)).await.unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, zero);
    assert_eq!(empty.sync_to, zero);
    assert!(!empty.has_more);
}

#[tokio::test]
async fn fixed_range_row_limit_excludes_later_candidates() {
    let (_dir, writer, reader) = database();
    for seed in 1..=503 {
        store_note(&writer, note(seed, 7), u64::MAX).await.unwrap();
    }
    let initial = fetch_notes(&reader, vec![], None, None).await.unwrap();
    let target = Cursor { sequence: 501, ..initial.sync_to };
    let first = fetch_notes(&reader, vec![7], None, Some(target)).await.unwrap();
    assert_eq!(
        first.notes.iter().map(|n| n.seq).collect::<Vec<_>>(),
        (1..=500).collect::<Vec<_>>()
    );
    assert!(first.has_more);
    let tail = fetch_notes(&reader, vec![7], Some(first.cursor), Some(target)).await.unwrap();
    assert_eq!(tail.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![501]);
    assert_eq!(tail.sync_to, target);
    assert!(!tail.has_more);
    let next = fetch_notes(&reader, vec![7], Some(target), None).await.unwrap();
    assert_eq!(next.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![502, 503]);
}

#[tokio::test]
async fn fixed_range_payload_limit_preserves_the_tail() {
    let (_dir, writer, reader) = database();
    let elements = FETCH_NOTES_MAX_BYTES / 3 / 8;
    for seed in 1..=4 {
        store_note(&writer, note_with_advice(seed, 7, elements), u64::MAX)
            .await
            .unwrap();
    }
    let head = fetch_notes(&reader, vec![], None, None).await.unwrap().sync_to;
    let target = Cursor { sequence: 3, ..head };
    let first = fetch_notes(&reader, vec![7], None, Some(target)).await.unwrap();
    assert_eq!(first.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert!(first.has_more);
    let tail = fetch_notes(&reader, vec![7], Some(first.cursor), Some(target)).await.unwrap();
    assert_eq!(tail.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![3]);
    assert!(!tail.has_more);
    assert_eq!(tail.sync_to, target);
}

#[tokio::test]
async fn watermark_survives_rollback_cleanup_and_reopening() {
    let (dir, writer, reader) = database();
    let original = note(1, 7);
    let limit =
        u64::try_from(encoded_note_payload_len(&original.header, &original.details).unwrap())
            .unwrap();
    store_note(&writer, original, limit).await.unwrap();
    assert!(matches!(
        store_note(&writer, note(2, 7), limit).await,
        Err(StorageError::Capacity(_))
    ));
    let head = fetch_notes(&reader, vec![], None, None).await.unwrap().sync_to;
    assert_eq!(head.sequence, 1);
    store_note(&writer, note(2, 7), u64::MAX).await.unwrap();
    let head = fetch_notes(&reader, vec![], None, None).await.unwrap().sync_to;
    assert_eq!(head.sequence, 2);
    writer
        .write("remove retained notes", |tx| {
            let removed = queries::delete_notes_created_before(tx, i64::MAX, 10)?;
            let retained = queries::select_retained_bytes(tx)?;
            queries::update_retained_bytes(tx, retained - removed)?;
            Ok::<_, StorageError>(())
        })
        .await
        .unwrap();
    drop((writer, reader));
    let (writer, reader) = load(&dir.path().join("notes.sqlite3")).unwrap();
    let empty = fetch_notes(&reader, vec![7], Some(head), Some(head)).await.unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.sync_to, head);
    assert_eq!(empty.cursor, head);
    assert!(!empty.has_more);
    store_note(&writer, note(3, 7), u64::MAX).await.unwrap();
    let next = fetch_notes(&reader, vec![7], Some(head), None).await.unwrap();
    assert_eq!(next.notes.iter().map(|n| n.seq).collect::<Vec<_>>(), vec![3]);
    assert_eq!(next.sync_to.sequence, 3);
    assert_eq!(next.sync_to.nonce, head.nonce);
}

#[tokio::test]
async fn bound_validation_accepts_equal_and_maximum_sequences() {
    let (_dir, writer, reader) = database();
    store_note(&writer, note(1, 7), u64::MAX).await.unwrap();
    let head = fetch_notes(&reader, vec![], None, None).await.unwrap().sync_to;
    let future = Cursor { sequence: 2, ..head };
    let zero = Cursor { sequence: 0, ..head };
    for (lower, upper) in [(Some(future), None), (None, Some(future)), (Some(head), Some(zero))] {
        assert!(matches!(
            fetch_notes(&reader, vec![], lower, upper).await,
            Err(StorageError::InvalidSyncRange)
        ));
    }
    writer
        .write("set allocation boundary", |tx| {
            tx.execute("UPDATE sqlite_sequence SET seq = ?1 WHERE name = 'notes'", &[&i64::MAX])?;
            Ok::<_, StorageError>(())
        })
        .await
        .unwrap();
    let max = Cursor { sequence: i64::MAX as u64, ..head };
    let empty = fetch_notes(&reader, vec![7], Some(max), Some(max)).await.unwrap();
    assert!(empty.notes.is_empty());
    assert_eq!(empty.cursor, max);
    assert_eq!(empty.sync_to, max);
    assert!(!empty.has_more);
}
