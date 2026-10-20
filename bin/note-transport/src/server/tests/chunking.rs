use super::fetch_ranges::{fetch, insert};
use super::*;

async fn drain_chunk(
    server: &Server,
    tags: Vec<u32>,
    mut cursor: Option<FetchNotesCursor>,
    mut target: Option<FetchNotesCursor>,
) -> (Vec<FetchedNote>, FetchNotesCursor) {
    let mut notes = Vec::new();
    loop {
        let page = fetch(server, tags.clone(), cursor, target).await.unwrap();
        let resolved = page.sync_to.expect("chunking requires a response target");
        if let Some(target) = target {
            assert_eq!(resolved, target);
        }
        assert_eq!(page.cursor.unwrap().nonce, resolved.nonce);
        assert!(page.cursor.unwrap().sequence <= resolved.sequence);
        if page.has_more {
            assert!(page.cursor.unwrap().sequence > cursor.map_or(0, |c| c.sequence));
        }
        notes.extend(page.notes);
        if !page.has_more {
            return (notes, resolved);
        }
        cursor = page.cursor;
        target = Some(resolved);
    }
}

fn note_ids(notes: &[FetchedNote]) -> std::collections::BTreeSet<miden_protocol::note::NoteId> {
    notes
        .iter()
        .map(|note| note.header.clone().unwrap().decode_fields().unwrap().verify().unwrap().id())
        .collect()
}

#[tokio::test]
async fn shared_round_covers_more_than_128_tags_and_defers_later_inserts() {
    let (_dir, server) = server(test_config());
    let mut expected = Vec::new();
    for serial in 1..=503 {
        expected.push(insert(&server, serial, 0).await);
    }
    for tag in 1..=256 {
        expected.push(insert(&server, 1000 + tag, tag).await);
    }
    let durable = None;
    let first = fetch(&server, (0..128).collect(), durable, None).await.unwrap();
    assert!(first.has_more);
    assert_eq!(first.notes.len(), 500);
    let target = first.sync_to.unwrap();
    assert_eq!(target.sequence, 759);
    let deferred_a = insert(&server, 9001, 0).await;
    let deferred_b = insert(&server, 9002, 200).await;
    let mut delivered = first.notes;
    let (tail, tail_target) =
        drain_chunk(&server, (0..128).collect(), first.cursor, Some(target)).await;
    assert_eq!(tail_target, target);
    delivered.extend(tail);
    for tags in [(128..256).collect(), vec![256, 999]] {
        let (notes, resolved) = drain_chunk(&server, tags, durable, Some(target)).await;
        assert_eq!(resolved, target);
        delivered.extend(notes);
    }
    assert_eq!(delivered, expected);
    assert_eq!(note_ids(&delivered).len(), delivered.len());
    // Only after all chunks succeeded would the client persist this cursor.
    let durable = Some(target);
    // Change the partition for the next round without retaining chunk cursors.
    let (first, next_target) = drain_chunk(&server, (0..64).collect(), durable, None).await;
    let mut next = first;
    for tags in [(64..192).collect(), (192..257).collect()] {
        let (notes, resolved) = drain_chunk(&server, tags, durable, Some(next_target)).await;
        assert_eq!(resolved, next_target);
        next.extend(notes);
    }
    assert_eq!(next, vec![deferred_a, deferred_b]);
    assert_eq!(next_target.sequence, 761);
}

#[tokio::test]
async fn retrying_an_interrupted_round_keeps_the_shared_lower_bound() {
    let (_dir, server) = server(test_config());
    let a = insert(&server, 1, 7).await;
    let b = insert(&server, 2, 8).await;
    let durable = None;
    let first = fetch(&server, vec![7], durable, None).await.unwrap();
    let target = first.sync_to.unwrap();
    assert_eq!(first.notes, vec![a.clone()]);
    let mut already_processed = note_ids(&first.notes);
    // A failed second request does not authorize advancement of the shared cursor.
    let error = fetch(&server, vec![8; 129], durable, Some(target)).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(durable, None);
    let (replay_a, resolved) = drain_chunk(&server, vec![7], durable, Some(target)).await;
    assert_eq!(resolved, target);
    assert_eq!(replay_a, vec![a]);
    let (replay_b, resolved) = drain_chunk(&server, vec![8], durable, Some(target)).await;
    assert_eq!(resolved, target);
    assert_eq!(replay_b, vec![b.clone()]);
    let mut newly_processed = Vec::new();
    for note in replay_a.into_iter().chain(replay_b) {
        let id = *note_ids(std::slice::from_ref(&note)).first().unwrap();
        if already_processed.insert(id) {
            newly_processed.push(note);
        }
    }
    assert_eq!(newly_processed, vec![b]);
    assert_eq!(already_processed.len(), 2);
    let durable = Some(target);
    assert_eq!(durable.map(|cursor| cursor.sequence), Some(2));
}

#[tokio::test]
async fn new_tags_backfill_only_their_history_then_join_the_shared_round() {
    let (_dir, server) = server(test_config());
    let a_old = insert(&server, 1, 7).await;
    let b_old = insert(&server, 2, 8).await;
    let (initial, shared) = drain_chunk(&server, vec![7], None, None).await;
    assert_eq!(initial, vec![a_old]);
    assert_eq!(shared.sequence, 2);
    let a_new = insert(&server, 3, 7).await;
    let b_new = insert(&server, 4, 8).await;
    let (backfill, target) = drain_chunk(&server, vec![8], None, Some(shared)).await;
    assert_eq!(target, shared);
    assert_eq!(backfill, vec![b_old]);
    let (live, target) = drain_chunk(&server, vec![7, 8], Some(shared), None).await;
    assert_eq!(live, vec![a_new, b_new]);
    assert_eq!(target.sequence, 4);
}

#[tokio::test]
async fn removed_tags_need_no_reset_and_newer_irrelevant_notes_do_not_repeat() {
    let (_dir, server) = server(test_config());
    insert(&server, 1, 7).await;
    insert(&server, 2, 8).await;
    let (_, shared) = drain_chunk(&server, vec![7, 8], None, None).await;
    let wanted = insert(&server, 3, 7).await;
    insert(&server, 4, 8).await;
    let (notes, next) = drain_chunk(&server, vec![7, 7], Some(shared), None).await;
    assert_eq!(notes, vec![wanted]);
    assert_eq!(next.sequence, 4);
    let (empty, resolved) = drain_chunk(&server, vec![7], Some(next), None).await;
    assert!(empty.is_empty());
    assert_eq!(resolved, next);
}
