use std::collections::{BTreeMap, BTreeSet, HashSet};

use diesel::prelude::{ExpressionMethods, QueryDsl, Queryable, QueryableByName, Selectable};
use diesel::query_dsl::methods::SelectDsl;
use diesel::sqlite::Sqlite;
use diesel::{RunQueryDsl, SelectableHelper, SqliteConnection};
use miden_node_utils::limiter::{QueryParamLimiter, QueryParamNoteCommitmentLimit};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNoteIndex, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    NoteAttachments,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteTag,
    NoteType,
    Nullifier,
    PartialNoteMetadata,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};

use crate::db::models::conv::{SqlTypeConvert, raw_sql_to_idx};
use crate::db::models::serialize_vec;
use crate::db::{DatabaseError, NoteSyncRecord, schema};

/// Select the requested note IDs that the notes table contains at or before `up_to_block`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     notes.note_id
/// FROM notes
/// WHERE note_id IN (?1) AND committed_at <= ?2
/// ```
pub(crate) fn select_existing_note_ids(
    conn: &mut SqliteConnection,
    note_ids: &[NoteId],
    up_to_block: BlockNumber,
) -> Result<HashSet<NoteId>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_ids.len())?;

    let note_ids = serialize_vec(note_ids);

    let raw_note_ids = SelectDsl::select(schema::notes::table, schema::notes::note_id)
        .filter(schema::notes::note_id.eq_any(&note_ids))
        .filter(schema::notes::committed_at.le(up_to_block.to_raw_sql()))
        .load::<Vec<u8>>(conn)?;

    let note_ids = raw_note_ids
        .into_iter()
        .map(|note_id| NoteId::read_from_bytes(&note_id))
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(note_ids)
}

/// Select note inclusion proofs matching the note commitments, restricted to notes committed at
/// or before `up_to_block`.
///
/// # Parameters
/// * `note_ids`: Set of note IDs to query
///     - Limit: 0 <= count <= 1000
/// * `up_to_block`: Only notes committed at or before this block are returned
///
/// # Returns
///
/// - Empty map if no matching `note`.
/// - Otherwise, note inclusion proofs, which `note_id` matches the `NoteId` as bytes.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     committed_at,
///     note_id,
///     batch_index,
///     note_index,
///     inclusion_path
/// FROM
///     notes
/// WHERE
///     note_id IN (?1) AND
///     committed_at <= ?2
/// ORDER BY
///     committed_at ASC
/// ```
pub(crate) fn select_note_inclusion_proofs(
    conn: &mut SqliteConnection,
    note_commitments: &BTreeSet<Word>,
    up_to_block: BlockNumber,
) -> Result<BTreeMap<NoteId, NoteInclusionProof>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_commitments.len())?;

    let note_commitments = serialize_vec(note_commitments.iter());

    let raw_notes = SelectDsl::select(
        schema::notes::table,
        (
            schema::notes::committed_at,
            schema::notes::note_id,
            schema::notes::batch_index,
            schema::notes::note_index,
            schema::notes::inclusion_path,
        ),
    )
    .filter(schema::notes::note_id.eq_any(note_commitments))
    .filter(schema::notes::committed_at.le(up_to_block.to_raw_sql()))
    .order_by(schema::notes::committed_at.asc())
    .load::<(i64, Vec<u8>, i32, i32, Vec<u8>)>(conn)?;

    raw_notes
        .iter()
        .map(|(block_num, note_id, batch_index, note_index, merkle_path)| {
            let note_id = NoteId::read_from_bytes(&note_id[..])?;
            let block_num = BlockNumber::from_raw_sql(*block_num)?;
            let node_index_in_block =
                BlockNoteIndex::new(raw_sql_to_idx(*batch_index), raw_sql_to_idx(*note_index))
                    .expect("batch and note index from DB should be valid")
                    .leaf_index_value();
            let merkle_path = miden_node_persistence::decode::<SparseMerklePath>(&merkle_path[..])?;
            let proof = NoteInclusionProof::new(block_num, node_index_in_block, merkle_path)?;
            Ok((note_id, proof))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

/// Select note sync records matching the given note commitments.
///
/// # Parameters
/// * `note_commitments`: Slice of note commitments to query
///     - Limit: 0 <= count <= 1000
///
/// # Returns
///
/// - Empty map if no matching `note`.
/// - Otherwise, note sync records keyed by `NoteId`.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     committed_at,
///     batch_index,
///     note_index,
///     note_id,
///     note_commitment,
///     note_type,
///     sender,
///     tag,
///     attachment,
///     inclusion_path
/// FROM
///     notes
/// WHERE
///     note_commitment IN (?1)
/// ORDER BY
///     committed_at ASC
/// ```
pub(crate) fn select_note_sync_records(
    conn: &mut SqliteConnection,
    note_ids: &[NoteId],
) -> Result<BTreeMap<NoteId, NoteSyncRecord>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_ids.len())?;

    let note_id_bytes: Vec<Vec<u8>> = note_ids.iter().map(|id| id.as_word().to_bytes()).collect();

    let raw_notes = SelectDsl::select(schema::notes::table, NoteSyncRecordRawRow::as_select())
        .filter(schema::notes::note_id.eq_any(note_id_bytes))
        .order_by(schema::notes::committed_at.asc())
        .load::<NoteSyncRecordRawRow>(conn)?;

    raw_notes
        .into_iter()
        .map(|raw_note| {
            let note: NoteSyncRecord = raw_note.try_into()?;
            Ok((note.note_id, note))
        })
        .collect()
}

/// Maps each given nullifier to its note ID.
///
/// Only public notes have a nullifier stored (`notes.nullifier` is NULL for private notes), so
/// private notes never match and are absent from the result.
///
/// ```sql
/// SELECT
///     nullifier,
///     note_id
/// FROM
///     notes
/// WHERE
///     nullifier IN (?1)
/// ```
pub(crate) fn select_note_ids_by_nullifier(
    conn: &mut SqliteConnection,
    nullifiers: &[Nullifier],
) -> Result<BTreeMap<Nullifier, NoteId>, DatabaseError> {
    if nullifiers.is_empty() {
        return Ok(BTreeMap::new());
    }

    let nullifier_bytes: Vec<Vec<u8>> = nullifiers.iter().map(Nullifier::to_bytes).collect();
    let pairs =
        SelectDsl::select(schema::notes::table, (schema::notes::nullifier, schema::notes::note_id))
            .filter(schema::notes::nullifier.eq_any(nullifier_bytes))
            .load::<(Option<Vec<u8>>, Vec<u8>)>(conn)?;

    let mut note_ids_by_nullifier = BTreeMap::new();
    for (nullifier, note_id) in pairs {
        let Some(nullifier) = nullifier else { continue };
        let nullifier = Nullifier::read_from_bytes(&nullifier)?;
        let note_id = NoteId::read_from_bytes(&note_id)?;
        note_ids_by_nullifier.insert(nullifier, note_id);
    }
    Ok(note_ids_by_nullifier)
}

#[derive(Debug, Clone, PartialEq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(Sqlite))]
pub struct NoteSyncRecordRawRow {
    pub committed_at: i64, // BlockNumber
    #[diesel(embed)]
    pub block_note_index: BlockNoteIndexRawRow,
    pub note_id: Vec<u8>, // BlobDigest
    #[diesel(embed)]
    pub metadata: NoteMetadataRawRow,
    pub inclusion_path: Vec<u8>, // SparseMerklePath
}

impl TryInto<NoteSyncRecord> for NoteSyncRecordRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<NoteSyncRecord, Self::Error> {
        let block_num = BlockNumber::from_raw_sql(self.committed_at)?;
        let note_index = self.block_note_index.try_into()?;

        let note_id = NoteId::from_raw(Word::read_from_bytes(&self.note_id[..])?);
        let inclusion_path =
            miden_node_persistence::decode::<SparseMerklePath>(&self.inclusion_path[..])?;
        let (metadata, attachments) = self.metadata.try_into()?;
        Ok(NoteSyncRecord {
            block_num,
            note_index,
            note_id,
            metadata,
            attachments,
            inclusion_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(Sqlite))]
pub struct NoteMetadataRawRow {
    note_type: i32,
    sender: Vec<u8>, // AccountId
    tag: i32,
    attachment: Vec<u8>,
}

#[expect(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
impl TryInto<(NoteMetadata, NoteAttachments)> for NoteMetadataRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<(NoteMetadata, NoteAttachments), Self::Error> {
        let sender = AccountId::read_from_bytes(&self.sender[..])?;
        let note_type = NoteType::try_from(self.note_type as u8)
            .map_err(miden_node_db::DatabaseError::conversiont_from_sql::<NoteType, _, _>)?;
        let tag = NoteTag::new(self.tag as u32);
        let attachments = miden_node_persistence::decode::<NoteAttachments>(&self.attachment)?;
        let partial = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let metadata = NoteMetadata::new(partial, &attachments);
        Ok((metadata, attachments))
    }
}

#[derive(Debug, Clone, PartialEq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(Sqlite))]
pub struct BlockNoteIndexRawRow {
    pub batch_index: i32,
    pub note_index: i32, // index within batch
}

#[expect(clippy::cast_sign_loss, reason = "Indices are cast to usize for ease of use")]
impl TryInto<BlockNoteIndex> for BlockNoteIndexRawRow {
    type Error = DatabaseError;
    fn try_into(self) -> Result<BlockNoteIndex, Self::Error> {
        let batch_index = self.batch_index as usize;
        let note_index = self.note_index as usize;
        let index = BlockNoteIndex::new(batch_index, note_index).ok_or_else(|| {
            miden_node_db::DatabaseError::conversiont_from_sql::<BlockNoteIndex, DatabaseError, _>(
                None,
            )
        })?;
        Ok(index)
    }
}
