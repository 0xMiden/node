use miden_protocol::Word;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_MAX_ZEROES;

use super::*;

fn note(seed: u32, tag: u32) -> StoredNote {
    let recipient = NoteRecipient::new(
        Word::from([seed, 0, 0, 0]),
        NoteScript::mock(),
        NoteStorage::new(vec![]).unwrap(),
    );
    let metadata =
        PartialNoteMetadata::new(ACCOUNT_ID_MAX_ZEROES.try_into().unwrap(), NoteType::Private)
            .with_tag(NoteTag::new(tag));
    let note = Note::new(NoteAssets::default(), metadata, recipient);
    StoredNote {
        header: *note.header(),
        details: miden_protocol::note::NoteDetails::from(note).to_bytes(),
        created_at: 0,
        seq: 0,
        after_block_num: Some(10),
    }
}

fn database() -> (tempfile::TempDir, DbWriter, DbReader) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite3");
    bootstrap(&path).unwrap();
    let (writer, reader) = load(&path).unwrap();
    (dir, writer, reader)
}

#[test]
fn lifecycle_rejects_missing_and_existing_databases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite3");
    assert!(load(&path).is_err());
    assert!(migrate(&path).is_err());
    bootstrap(&path).unwrap();
    assert!(bootstrap(&path).is_err());
    migrate(&path).unwrap();
}

#[tokio::test]
async fn load_rejects_an_unknown_schema() {
    let (dir, writer, reader) = database();
    writer
        .write("alter schema", |tx| {
            tx.execute("CREATE TABLE unknown_data (value INTEGER) STRICT", &[])?;
            Ok::<_, miden_node_db::DatabaseError>(())
        })
        .await
        .unwrap();
    drop((writer, reader));

    assert!(load(&dir.path().join("notes.sqlite3")).is_err());
}

#[tokio::test]
async fn retained_note_roundtrips_after_reopening() {
    let (dir, writer, reader) = database();
    let mut original = note(7, u32::MAX);
    original.created_at = 1_800_000_000_123_456;
    original.after_block_num = Some(u32::MAX);
    store_note(&writer, original.clone(), u64::MAX).await.unwrap();
    drop((writer, reader));

    let (_writer, reader) = load(&dir.path().join("notes.sqlite3")).unwrap();
    let page = fetch_notes(&reader, vec![u32::MAX], 0).await.unwrap();
    assert_eq!(page.notes.len(), 1);
    let retained = &page.notes[0];
    assert_eq!(retained.header, original.header);
    assert_eq!(retained.details, original.details);
    assert_eq!(retained.after_block_num, original.after_block_num);
    assert_eq!(retained.created_at, original.created_at);
    assert_eq!(retained.seq, 1);
    assert!(!page.has_more);
}

#[tokio::test]
async fn retry_at_capacity_preserves_first_write() {
    let (_dir, writer, reader) = database();
    let original = note(1, 42);
    let limit = (original.header.to_bytes().len() + original.details.len()) as u64;
    assert_eq!(
        store_note(&writer, original.clone(), limit).await.unwrap(),
        StoreResult::Inserted
    );
    let mut retry = original.clone();
    retry.after_block_num = Some(99);
    retry.created_at = 123;
    assert_eq!(store_note(&writer, retry, limit).await.unwrap(), StoreResult::AlreadyPresent);
    assert!(matches!(
        store_note(&writer, note(2, 42), limit).await,
        Err(StorageError::Capacity(_))
    ));
    let page = fetch_notes(&reader, vec![42], 0).await.unwrap();
    assert_eq!(page.notes.len(), 1);
    assert_eq!(page.notes[0].after_block_num, original.after_block_num);
    assert_eq!(page.notes[0].created_at, original.created_at);
    assert_eq!(page.notes[0].seq, 1);
    assert!(!page.has_more);
}

#[tokio::test]
async fn cleanup_releases_capacity_without_reusing_cursors() {
    let (dir, writer, reader) = database();
    let original = note(1, 42);
    let limit = (original.header.to_bytes().len() + original.details.len()) as u64 * 2;
    for seed in 1..=2 {
        store_note(&writer, note(seed, 42), limit).await.unwrap();
    }
    assert_eq!(cleanup(&writer, 30, 1).await.unwrap(), 1);
    assert_eq!(cleanup(&writer, 30, 1).await.unwrap(), 1);
    drop((writer, reader));
    let (writer, reader) = load(&dir.path().join("notes.sqlite3")).unwrap();
    store_note(&writer, note(3, 42), limit).await.unwrap();
    assert_eq!(fetch_notes(&reader, vec![42], 2).await.unwrap().notes[0].seq, 3);
}

#[tokio::test]
async fn cleanup_preserves_recent_notes_and_respects_zero_and_maximum_limits() {
    let (_dir, writer, reader) = database();
    let old = note(1, 42);
    let mut recent = note(2, 42);
    recent.created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap();
    store_note(&writer, old.clone(), u64::MAX).await.unwrap();
    store_note(&writer, recent.clone(), u64::MAX).await.unwrap();

    assert_eq!(cleanup(&writer, 30, 0).await.unwrap(), 0);
    assert_eq!(cleanup(&writer, u32::MAX, 1000).await.unwrap(), 0);
    let page = fetch_notes(&reader, vec![42], 0).await.unwrap();
    assert_eq!(
        page.notes.iter().map(|item| item.header.id()).collect::<Vec<_>>(),
        vec![old.header.id(), recent.header.id()]
    );

    assert_eq!(cleanup(&writer, 30, 1000).await.unwrap(), 1);
    let page = fetch_notes(&reader, vec![42], 0).await.unwrap();
    assert_eq!(page.notes.len(), 1);
    assert_eq!(page.notes[0].header.id(), recent.header.id());
    assert!(!page.has_more);
}

#[tokio::test]
async fn multi_tag_fetch_has_stable_bounded_pages() {
    let (_dir, writer, reader) = database();
    for seed in 1..=503 {
        store_note(&writer, note(seed, seed % 2), u64::MAX).await.unwrap();
    }
    let page = fetch_notes(&reader, vec![1, 0, 1], 0).await.unwrap();
    assert_eq!(page.notes.len(), FETCH_NOTES_MAX_ROWS);
    assert!(page.has_more);
    assert_eq!(
        page.notes.iter().map(|n| n.seq).collect::<Vec<_>>(),
        (1..=500).collect::<Vec<_>>()
    );
    let page = fetch_notes(&reader, vec![0, 1], 500).await.unwrap();
    assert_eq!(page.notes.len(), 3);
    assert!(!page.has_more);
    assert!(fetch_notes(&reader, vec![], 0).await.unwrap().notes.is_empty());
    assert!(matches!(
        fetch_notes(&reader, vec![1], u64::MAX).await,
        Err(StorageError::InvalidCursor)
    ));
}

#[tokio::test]
async fn fetch_byte_limit_and_oversize_rejection() {
    let (_dir, writer, reader) = database();
    for seed in 1..=3 {
        let mut item = note(seed, 42);
        item.details = vec![0; FETCH_NOTES_MAX_BYTES / 2 - item.header.to_bytes().len()];
        store_note(&writer, item, u64::MAX).await.unwrap();
    }
    let page = fetch_notes(&reader, vec![42], 0).await.unwrap();
    assert_eq!(page.notes.len(), 2);
    assert!(page.has_more);
    assert_eq!(fetch_notes(&reader, vec![42], 2).await.unwrap().notes.len(), 1);
    let mut oversized = note(4, 42);
    oversized.details = vec![0; FETCH_NOTES_MAX_BYTES];
    assert!(matches!(
        store_note(&writer, oversized, u64::MAX).await,
        Err(StorageError::Capacity(_))
    ));
}

#[tokio::test]
async fn cursor_exhaustion_rejects_insert_without_losing_existing_notes() {
    let (_dir, writer, reader) = database();
    store_note(&writer, note(1, 42), u64::MAX).await.unwrap();
    writer
        .write("exhaust cursor", |tx| {
            tx.execute("UPDATE storage_metadata SET next_cursor = ?1", &[&i64::MAX])?;
            Ok::<_, miden_node_db::DatabaseError>(())
        })
        .await
        .unwrap();
    assert!(matches!(
        store_note(&writer, note(2, 42), u64::MAX).await,
        Err(StorageError::Capacity(_))
    ));
    assert_eq!(
        store_note(&writer, note(1, 42), u64::MAX).await.unwrap(),
        StoreResult::AlreadyPresent
    );
    assert_eq!(fetch_notes(&reader, vec![42], 0).await.unwrap().notes.len(), 1);
}

#[tokio::test]
async fn failed_insert_rolls_back_capacity_and_cursor() {
    let (_dir, writer, reader) = database();
    writer.write("reject insertion", |tx| {
        tx.execute("CREATE TRIGGER reject_note BEFORE INSERT ON notes BEGIN SELECT RAISE(ABORT, 'rejected'); END", &[])?;
        Ok::<_, miden_node_db::DatabaseError>(())
    }).await.unwrap();
    let item = note(1, 42);
    let limit = (item.header.to_bytes().len() + item.details.len()) as u64;
    assert!(store_note(&writer, item.clone(), limit).await.is_err());
    writer
        .write("allow insertion", |tx| {
            tx.execute("DROP TRIGGER reject_note", &[])?;
            Ok::<_, miden_node_db::DatabaseError>(())
        })
        .await
        .unwrap();
    store_note(&writer, item, limit).await.unwrap();
    assert_eq!(fetch_notes(&reader, vec![42], 0).await.unwrap().notes[0].seq, 1);
}

#[tokio::test]
async fn concurrent_writes_share_capacity() {
    let (_dir, writer, reader) = database();
    let item = note(1, 42);
    let limit = (item.header.to_bytes().len() + item.details.len()) as u64;
    let (first, second) =
        tokio::join!(store_note(&writer, item, limit), store_note(&writer, note(2, 42), limit),);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(fetch_notes(&reader, vec![42], 0).await.unwrap().notes.len(), 1);
}
