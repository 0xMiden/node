#![expect(
    clippy::cast_possible_wrap,
    reason = "We will not approach the item count where i64 and usize cause issues"
)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::RangeInclusive;

use diesel::prelude::{
    BoolExpressionMethods,
    ExpressionMethods,
    Insertable,
    QueryDsl,
    Queryable,
    QueryableByName,
    Selectable,
};
use diesel::query_dsl::methods::SelectDsl;
use diesel::sqlite::Sqlite;
use diesel::{
    JoinOnDsl,
    NullableExpressionMethods,
    OptionalExtension,
    RunQueryDsl,
    SelectableHelper,
    SqliteConnection,
};
use miden_node_utils::limiter::{
    QueryParamLimiter,
    QueryParamNoteCommitmentLimit,
    QueryParamNoteTagLimit,
};
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNoteIndex, BlockNumber};
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    NoteAssets,
    NoteAttachments,
    NoteDetails,
    NoteId,
    NoteInclusionProof,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
    Nullifier,
    PartialNoteMetadata,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::note::NetworkAccountTarget;

use crate::COMPONENT;
use crate::db::models::conv::{
    SqlTypeConvert,
    idx_to_raw_sql,
    note_type_to_raw_sql,
    raw_sql_to_idx,
};
use crate::db::models::queries::select_block_header_by_block_num;
use crate::db::models::{serialize_vec, vec_raw_try_into};
use crate::db::{DatabaseError, NoteRecord, NoteSyncRecord, NoteSyncUpdate, Page, schema};
use crate::errors::NoteSyncError;

/// Estimated byte size of a [`NoteSyncUpdate`] excluding its notes.
///
/// `BlockHeader` (~341 bytes) + MMR proof with 32 siblings (~1216 bytes).
pub(crate) const NOTE_SYNC_BLOCK_OVERHEAD_BYTES: usize = 1600;

/// Estimated byte size of a single [`NoteSyncRecord`].
///
/// Note ID (~38 bytes) + index + metadata (~26 bytes) + sparse merkle path with 16 siblings
/// (~608 bytes).
pub(crate) const NOTE_SYNC_RECORD_BYTES: usize = 700;

// NETWORK NOTE TYPE
// ================================================================================================

/// Classifies network notes for database storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub(crate) enum NetworkNoteType {
    /// Not a network note.
    None = 0,
    /// Single account target network note (has `NetworkAccountTarget` attachment).
    SingleTarget = 1,
}

impl From<NetworkNoteType> for i32 {
    fn from(value: NetworkNoteType) -> Self {
        value as i32
    }
}

/// Select notes matching the given tags within a block range.
///
/// # Parameters
/// * `note_tags`: List of note tags to filter by
///     - Limit: 0 <= count <= 1000
/// * `block_range`: Range of blocks to search (inclusive)
///
/// # Returns
///
/// All matching notes from the first block within the range containing a matching note. If no
/// matching notes are found at all, then an empty vector is returned.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     committed_at,
///     batch_index,
///     note_index,
///     note_id,
///     note_type,
///     sender,
///     tag,
///     attachment,
///     inclusion_path
/// FROM
///     notes
/// WHERE
///     committed_at = (
///         SELECT
///             committed_at
///         FROM
///             notes
///         WHERE
///             tag IN (?1) AND
///             committed_at >= ?2 AND
///             committed_at <= ?3
///         ORDER BY
///             committed_at ASC
///         LIMIT 1
///     ) AND
///     tag IN (?1)
/// ORDER BY
///     committed_at ASC, batch_index ASC, note_index ASC
/// ```
pub(crate) fn select_notes_since_block_by_tag(
    conn: &mut SqliteConnection,
    note_tags: &[u32],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<Vec<NoteSyncRecord>, DatabaseError> {
    QueryParamNoteTagLimit::check(note_tags.len())?;
    let desired_note_tags: Vec<i32> = note_tags.iter().map(|tag| *tag as i32).collect();
    let start_block_num = block_range.start().to_raw_sql();
    let end_block_num = block_range.end().to_raw_sql();

    let Some(desired_block_num): Option<i64> =
        SelectDsl::select(schema::notes::table, schema::notes::committed_at)
            .filter(schema::notes::tag.eq_any(&desired_note_tags))
            .filter(schema::notes::committed_at.ge(start_block_num))
            .filter(schema::notes::committed_at.le(end_block_num))
            .order_by(schema::notes::committed_at.asc())
            .limit(1)
            .get_result(conn)
            .optional()?
    else {
        return Ok(Vec::new());
    };

    let notes = SelectDsl::select(schema::notes::table, NoteSyncRecordRawRow::as_select())
        .filter(schema::notes::committed_at.eq(desired_block_num))
        .filter(schema::notes::tag.eq_any(&desired_note_tags))
        .order_by((
            schema::notes::committed_at.asc(),
            schema::notes::batch_index.asc(),
            schema::notes::note_index.asc(),
        ))
        .get_results::<NoteSyncRecordRawRow>(conn)
        .map_err(DatabaseError::from)?;

    vec_raw_try_into(notes)
}

/// Select all notes matching the given set of identifiers
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     notes.committed_at,
///     notes.batch_index,
///     notes.note_index,
///     notes.note_id,
///     notes.note_type,
///     notes.sender,
///     notes.tag,
///     notes.attachment,
///     notes.assets,
///     notes.storage,
///     notes.serial_num,
///     notes.inclusion_path,
///     note_scripts.script
/// FROM notes
/// LEFT JOIN note_scripts ON notes.script_root = note_scripts.script_root
/// WHERE note_id IN (?1)
/// ```
pub(crate) fn select_notes_by_id(
    conn: &mut SqliteConnection,
    note_ids: &[NoteId],
) -> Result<Vec<NoteRecord>, DatabaseError> {
    let note_ids = serialize_vec(note_ids);
    let q = schema::notes::table
        .left_join(
            schema::note_scripts::table
                .on(schema::notes::script_root.eq(schema::note_scripts::script_root.nullable())),
        )
        .filter(schema::notes::note_id.eq_any(&note_ids));
    let raw: Vec<_> = SelectDsl::select(
        q,
        (NoteRecordRawRow::as_select(), schema::note_scripts::script.nullable()),
    )
    .load::<(NoteRecordRawRow, Option<Vec<u8>>)>(conn)?;
    let records = vec_raw_try_into::<NoteRecord, NoteRecordWithScriptRawJoined>(
        raw.into_iter().map(NoteRecordWithScriptRawJoined::from),
    )?;
    Ok(records)
}

/// Select the subset of note commitments that already exist in the notes table
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     notes.note_commitment
/// FROM notes
/// WHERE note_commitment IN (?1)
/// ```
pub(crate) fn select_existing_note_commitments(
    conn: &mut SqliteConnection,
    note_commitments: &[Word],
) -> Result<HashSet<Word>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_commitments.len())?;

    let note_commitments = serialize_vec(note_commitments.iter());

    let raw_commitments = SelectDsl::select(schema::notes::table, schema::notes::note_commitment)
        .filter(schema::notes::note_commitment.eq_any(&note_commitments))
        .load::<Vec<u8>>(conn)?;

    let commitments = raw_commitments
        .into_iter()
        .map(|commitment| Word::read_from_bytes(&commitment[..]))
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(commitments)
}

/// Select all notes from the DB using the given [`SqliteConnection`].
///
///
/// # Returns
///
/// A vector with notes, or an error.
///
/// # Raw SQL
///
/// ```sql
/// SELECT
///     notes.committed_at,
///     notes.batch_index,
///     notes.note_index,
///     notes.note_id,
///     notes.note_type,
///     notes.sender,
///     notes.tag,
///     notes.attachment,
///     notes.assets,
///     notes.storage,
///     notes.serial_num,
///     notes.inclusion_path,
///     note_scripts.script
/// FROM notes
/// LEFT JOIN note_scripts ON notes.script_root = note_scripts.script_root
/// ORDER BY committed_at ASC
/// ```
#[cfg(test)]
pub(crate) fn select_all_notes(
    conn: &mut SqliteConnection,
) -> Result<Vec<NoteRecord>, DatabaseError> {
    let q = schema::notes::table.left_join(
        schema::note_scripts::table
            .on(schema::notes::script_root.eq(schema::note_scripts::script_root.nullable())),
    );
    let raw: Vec<_> = SelectDsl::select(
        q,
        (NoteRecordRawRow::as_select(), schema::note_scripts::script.nullable()),
    )
    .order(schema::notes::committed_at.asc())
    .load::<(NoteRecordRawRow, Option<Vec<u8>>)>(conn)?;
    let records = vec_raw_try_into::<NoteRecord, NoteRecordWithScriptRawJoined>(
        raw.into_iter().map(NoteRecordWithScriptRawJoined::from),
    )?;
    Ok(records)
}

/// Select note inclusion proofs matching the note commitments.
///
/// # Parameters
/// * `note_ids`: Set of note IDs to query
///     - Limit: 0 <= count <= 1000
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
///     note_id IN (?1)
/// ORDER BY
///     committed_at ASC
/// ```
pub(crate) fn select_note_inclusion_proofs(
    conn: &mut SqliteConnection,
    note_commitments: &BTreeSet<Word>,
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
    .filter(schema::notes::note_commitment.eq_any(note_commitments))
    .order_by(schema::notes::committed_at.asc())
    .load::<(i64, Vec<u8>, i32, i32, Vec<u8>)>(conn)?;

    Result::<BTreeMap<_, _>, _>::from_iter(raw_notes.iter().map(
        |(block_num, note_id, batch_index, note_index, merkle_path)| {
            let note_id = NoteId::read_from_bytes(&note_id[..])?;
            let block_num = BlockNumber::from_raw_sql(*block_num)?;
            let node_index_in_block =
                BlockNoteIndex::new(raw_sql_to_idx(*batch_index), raw_sql_to_idx(*note_index))
                    .expect("batch and note index from DB should be valid")
                    .leaf_index_value();
            let merkle_path = SparseMerklePath::read_from_bytes(&merkle_path[..])?;
            let proof = NoteInclusionProof::new(block_num, node_index_in_block, merkle_path)?;
            Ok((note_id, proof))
        },
    ))
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
    note_commitments: &[Word],
) -> Result<BTreeMap<NoteId, NoteSyncRecord>, DatabaseError> {
    QueryParamNoteCommitmentLimit::check(note_commitments.len())?;

    let note_commitments = serialize_vec(note_commitments.iter());

    let raw_notes = SelectDsl::select(schema::notes::table, NoteSyncRecordRawRow::as_select())
        .filter(schema::notes::note_commitment.eq_any(note_commitments))
        .order_by(schema::notes::committed_at.asc())
        .load::<NoteSyncRecordRawRow>(conn)?;

    raw_notes
        .into_iter()
        .map(|raw_note| {
            let note: NoteSyncRecord = raw_note.try_into()?;
            Ok((NoteId::from_raw(note.note_id), note))
        })
        .collect()
}

/// Returns the script for a note by its root.
///
/// ```sql
/// SELECT
///     script_root,
///     script
/// FROM
///     note_scripts
/// WHERE
///     script_root = ?1
/// ```
pub(crate) fn select_note_script_by_root(
    conn: &mut SqliteConnection,
    root: Word,
) -> Result<Option<NoteScript>, DatabaseError> {
    let raw = SelectDsl::select(schema::note_scripts::table, schema::note_scripts::script)
        .filter(schema::note_scripts::script_root.eq(root.to_bytes()))
        .get_result::<Vec<u8>>(conn)
        .optional()?;

    raw.as_ref()
        .map(|bytes| NoteScript::from_bytes(bytes))
        .transpose()
        .map_err(Into::into)
}

/// Returns a paginated batch of network notes for an account that are unconsumed by a specified
/// block number.
///
///  Notes that are created or consumed after the specified block are excluded from the result.
///
/// # Returns
///
/// A set of unconsumed network notes with maximum length of `size` and the page to get
/// the next set.
///
/// # Raw SQL
///
/// Attention: uses the _implicit_ column `rowid`, which requires to use a few raw SQL nugget
/// statements.
///
/// ```sql
/// SELECT
///     notes.committed_at,
///     notes.batch_index,
///     notes.note_index,
///     notes.note_id,
///     notes.note_type,
///     notes.sender,
///     notes.tag,
///     notes.attachment,
///     notes.assets,
///     notes.storage,
///     notes.serial_num,
///     notes.inclusion_path,
///     note_scripts.script,
///     notes.rowid
/// FROM notes
/// LEFT JOIN note_scripts ON notes.script_root = note_scripts.script_root
/// WHERE
///     network_note_type = 1 AND target_account_id = ?1 AND
///     committed_at <= ?2 AND
///     (consumed_at IS NULL OR consumed_at > ?2) AND notes.rowid >= ?3
/// ORDER BY notes.rowid ASC
/// LIMIT ?4
/// ```
#[expect(clippy::cast_sign_loss, reason = "row_id is a positive integer")]
pub(crate) fn select_unconsumed_network_notes_by_account_id(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    block_num: BlockNumber,
    mut page: Page,
) -> Result<(Vec<NoteRecord>, Page), DatabaseError> {
    let rowid_sel = diesel::dsl::sql::<diesel::sql_types::BigInt>("notes.rowid");
    let rowid_sel_ge =
        diesel::dsl::sql::<diesel::sql_types::Bool>("notes.rowid >= ")
            .bind::<diesel::sql_types::BigInt, i64>(page.token.unwrap_or_default() as i64);

    #[expect(
        clippy::items_after_statements,
        reason = "It's only relevant for a single call function"
    )]
    type RawLoadedTuple = (
        NoteRecordRawRow,
        Option<Vec<u8>>, // script
        i64,             // rowid (from sql::<BigInt>("notes.rowid"))
    );

    #[expect(
        clippy::items_after_statements,
        reason = "It's only relevant for a single call function"
    )]
    fn split_into_raw_note_record_and_implicit_row_id(
        tuple: RawLoadedTuple,
    ) -> (NoteRecordWithScriptRawJoined, i64) {
        let (note, script, row) = tuple;
        let combined = NoteRecordWithScriptRawJoined::from((note, script));
        (combined, row)
    }

    let raw = SelectDsl::select(
        schema::notes::table.left_join(
            schema::note_scripts::table
                .on(schema::notes::script_root.eq(schema::note_scripts::script_root.nullable())),
        ),
        (
            NoteRecordRawRow::as_select(),
            schema::note_scripts::script.nullable(),
            rowid_sel.clone(),
        ),
    )
    .filter(schema::notes::network_note_type.eq(i32::from(NetworkNoteType::SingleTarget)))
    .filter(schema::notes::target_account_id.eq(Some(account_id.to_bytes())))
    .filter(schema::notes::committed_at.le(block_num.to_raw_sql()))
    .filter(
        schema::notes::consumed_at
            .is_null()
            .or(schema::notes::consumed_at.gt(block_num.to_raw_sql())),
    )
    .filter(rowid_sel_ge)
    .order(rowid_sel.asc())
    .limit(page.size.get() as i64 + 1)
    .load::<RawLoadedTuple>(conn)?;

    let mut notes = Vec::with_capacity(page.size.into());
    for raw_item in raw {
        let (raw_item, row_id) = split_into_raw_note_record_and_implicit_row_id(raw_item);
        page.token = None;
        if notes.len() == page.size.get() {
            page.token = Some(row_id as u64);
            break;
        }
        notes.push(TryInto::<NoteRecord>::try_into(raw_item)?);
    }

    Ok((notes, page))
}

/// Loads the data necessary for a note sync across all matching blocks in the given range.
///
/// Returns one [`NoteSyncUpdate`] per block that contains at least one note matching the
/// requested tags, ordered by block number ascending.
pub(crate) fn get_note_sync_multi(
    conn: &mut SqliteConnection,
    note_tags: &[u32],
    block_range: RangeInclusive<BlockNumber>,
    max_response_payload_bytes: usize,
) -> Result<Vec<NoteSyncUpdate>, NoteSyncError> {
    let mut current_from = *block_range.start();
    let block_end = *block_range.end();
    let mut updates = Vec::new();
    let mut accumulated_size = 0usize;

    loop {
        let notes = select_notes_since_block_by_tag(conn, note_tags, current_from..=block_end)?;

        let Some(block_num) = notes.first().map(|note| note.block_num) else {
            break;
        };

        accumulated_size += NOTE_SYNC_BLOCK_OVERHEAD_BYTES + notes.len() * NOTE_SYNC_RECORD_BYTES;

        if !updates.is_empty() && accumulated_size > max_response_payload_bytes {
            break;
        }

        let block_header = select_block_header_by_block_num(conn, Some(block_num))?
            .ok_or(NoteSyncError::EmptyBlockHeadersTable)?;
        updates.push(NoteSyncUpdate { notes, block_header });
        current_from = block_num + 1;
    }

    Ok(updates)
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

        let note_id = Word::read_from_bytes(&self.note_id[..])?;
        let inclusion_path = SparseMerklePath::read_from_bytes(&self.inclusion_path[..])?;
        let (metadata, _attachments) = self.metadata.try_into()?;
        Ok(NoteSyncRecord {
            block_num,
            note_index,
            note_id,
            metadata,
            inclusion_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(Sqlite))]
pub struct NoteDetailsRawRow {
    pub assets: Option<Vec<u8>>,
    pub storage: Option<Vec<u8>>,
    pub serial_num: Option<Vec<u8>>,
}

// Note: One cannot use `#[diesel(embed)]` to structure this, it will yield a significant amount of
// errors when used with join and debugging is painful to put it mildly.
#[derive(Debug, Clone, PartialEq, Queryable)]
pub struct NoteRecordWithScriptRawJoined {
    pub committed_at: i64,

    pub batch_index: i32,
    pub note_index: i32, // index within batch
    // #[diesel(embed)]
    // pub note_index: BlockNoteIndexRaw,
    pub note_id: Vec<u8>,
    pub note_commitment: Vec<u8>,

    pub note_type: i32,
    pub sender: Vec<u8>, // AccountId
    pub tag: i32,
    pub attachment: Vec<u8>,
    // #[diesel(embed)]
    // pub metadata: NoteMetadataRaw,
    pub assets: Option<Vec<u8>>,
    pub storage: Option<Vec<u8>>,
    pub serial_num: Option<Vec<u8>>,

    // #[diesel(embed)]
    // pub details: NoteDetailsRaw,
    pub inclusion_path: Vec<u8>,
    pub script: Option<Vec<u8>>, // not part of notes::table!
}

impl From<(NoteRecordRawRow, Option<Vec<u8>>)> for NoteRecordWithScriptRawJoined {
    fn from((note, script): (NoteRecordRawRow, Option<Vec<u8>>)) -> Self {
        let NoteRecordRawRow {
            committed_at,
            batch_index,
            note_index,
            note_id,
            note_commitment,
            note_type,
            sender,
            tag,
            attachment,
            assets,
            storage,
            serial_num,
            inclusion_path,
        } = note;
        Self {
            committed_at,
            batch_index,
            note_index,
            note_id,
            note_commitment,
            note_type,
            sender,
            tag,
            attachment,
            assets,
            storage,
            serial_num,
            inclusion_path,
            script,
        }
    }
}

impl TryInto<NoteRecord> for NoteRecordWithScriptRawJoined {
    type Error = DatabaseError;
    fn try_into(self) -> Result<NoteRecord, Self::Error> {
        // let (raw, script) = self;
        let raw = self;
        let NoteRecordWithScriptRawJoined {
            committed_at,

            batch_index,
            note_index,
            // block note index ^^^
            note_id,
            note_commitment,

            note_type,
            sender,
            tag,
            attachment,
            // metadata ^^^,
            assets,
            storage,
            serial_num,
            // details ^^^,
            inclusion_path,
            script,
            ..
        } = raw;
        let index = BlockNoteIndexRawRow { batch_index, note_index };
        let metadata = NoteMetadataRawRow { note_type, sender, tag, attachment };
        let details = NoteDetailsRawRow { assets, storage, serial_num };

        let (metadata, attachments) = metadata.try_into()?;
        let committed_at = BlockNumber::from_raw_sql(committed_at)?;
        let note_id = Word::read_from_bytes(&note_id[..])?;
        let note_commitment = Word::read_from_bytes(&note_commitment[..])?;
        let script = script.map(|script| NoteScript::read_from_bytes(&script[..])).transpose()?;
        let details = if let NoteDetailsRawRow {
            assets: Some(assets),
            storage: Some(storage),
            serial_num: Some(serial_num),
        } = details
        {
            let storage = NoteStorage::read_from_bytes(&storage[..])?;
            let serial_num = Word::read_from_bytes(&serial_num[..])?;
            let script =
                script.ok_or_else(|| {
                    miden_node_db::DatabaseError::conversiont_from_sql::<
                        NoteRecipient,
                        DatabaseError,
                        _,
                    >(None)
                })?;
            let recipient = NoteRecipient::new(serial_num, script, storage);
            let assets = NoteAssets::read_from_bytes(&assets[..])?;
            Some(NoteDetails::new(assets, recipient))
        } else {
            None
        };
        let inclusion_path = SparseMerklePath::read_from_bytes(&inclusion_path[..])?;
        let note_index = index.try_into()?;
        Ok(NoteRecord {
            block_num: committed_at,
            note_index,
            note_id,
            note_commitment,
            metadata,
            details,
            attachments,
            inclusion_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Selectable, Queryable, QueryableByName)]
#[diesel(table_name = schema::notes)]
#[diesel(check_for_backend(Sqlite))]
pub struct NoteRecordRawRow {
    pub committed_at: i64,

    pub batch_index: i32,
    pub note_index: i32, // index within batch
    pub note_id: Vec<u8>,
    pub note_commitment: Vec<u8>,

    pub note_type: i32,
    pub sender: Vec<u8>, // AccountId
    pub tag: i32,
    pub attachment: Vec<u8>,

    pub assets: Option<Vec<u8>>,
    pub storage: Option<Vec<u8>>,
    pub serial_num: Option<Vec<u8>>,

    pub inclusion_path: Vec<u8>,
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
        let attachments = if self.attachment.is_empty() {
            NoteAttachments::empty()
        } else {
            NoteAttachments::read_from_bytes(&self.attachment)?
        };
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

/// Insert notes to the DB using the given [`SqliteConnection`]. Public notes should also have a
/// nullifier.
///
/// # Returns
///
/// The number of affected rows.
///
/// # Note
///
/// The [`SqliteConnection`] object is not consumed. It's up to the caller to commit or rollback the
/// transaction.
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn insert_notes(
    conn: &mut SqliteConnection,
    notes: &[(NoteRecord, Option<Nullifier>)],
) -> Result<usize, DatabaseError> {
    let count = diesel::insert_into(schema::notes::table)
        .values(Vec::from_iter(
            notes
                .iter()
                .map(|(note, nullifier)| NoteInsertRow::from((note.clone(), *nullifier))),
        ))
        .execute(conn)?;
    Ok(count)
}

/// Insert scripts to the DB using the given [`SqliteConnection`]. It inserts the scripts held by
/// the notes passed as parameter. If the script root already exists in the DB, it will be ignored.
///
/// # Returns
///
/// The number of affected rows.
///
/// # Note
///
/// The [`SqliteConnection`] object is not consumed. It's up to the caller to commit or rollback the
/// transaction.
#[tracing::instrument(
    target = COMPONENT,
    skip_all,
    err,
)]
pub(crate) fn insert_scripts<'a>(
    conn: &mut SqliteConnection,
    notes: impl IntoIterator<Item = &'a NoteRecord>,
) -> Result<usize, DatabaseError> {
    let values = Vec::from_iter(notes.into_iter().filter_map(|note| {
        let note_details = note.details.as_ref()?;
        Some((
            schema::note_scripts::script_root.eq(note_details.script().root().to_bytes()),
            schema::note_scripts::script.eq(note_details.script().to_bytes()),
        ))
    }));
    let count = diesel::insert_or_ignore_into(schema::note_scripts::table)
        .values(values)
        .execute(conn)?;

    Ok(count)
}

#[derive(Debug, Clone, PartialEq, Insertable)]
#[diesel(table_name = schema::notes)]
pub struct NoteInsertRow {
    pub committed_at: i64,

    pub batch_index: i32,
    pub note_index: i32, // index within batch

    pub note_id: Vec<u8>,
    pub note_commitment: Vec<u8>,

    pub note_type: i32,
    pub sender: Vec<u8>, // AccountId
    pub tag: i32,

    pub network_note_type: i32,
    pub target_account_id: Option<Vec<u8>>,
    pub attachment: Vec<u8>,
    pub inclusion_path: Vec<u8>,
    pub consumed_at: Option<i64>,
    pub nullifier: Option<Vec<u8>>,
    pub assets: Option<Vec<u8>>,
    pub storage: Option<Vec<u8>>,
    pub script_root: Option<Vec<u8>>,
    pub serial_num: Option<Vec<u8>>,
}

impl From<(NoteRecord, Option<Nullifier>)> for NoteInsertRow {
    fn from((note, nullifier): (NoteRecord, Option<Nullifier>)) -> Self {
        let target_account_id = NetworkAccountTarget::try_from(&note.attachments).ok();
        let network_note_type = if target_account_id.is_some() && !note.metadata.is_private() {
            NetworkNoteType::SingleTarget
        } else {
            NetworkNoteType::None
        };

        let attachment_bytes = note.attachments.to_bytes();

        Self {
            committed_at: note.block_num.to_raw_sql(),
            batch_index: idx_to_raw_sql(note.note_index.batch_idx()),
            note_index: idx_to_raw_sql(note.note_index.note_idx_in_batch()),
            note_id: note.note_id.to_bytes(),
            note_commitment: note.note_commitment.to_bytes(),
            note_type: note_type_to_raw_sql(note.metadata.note_type() as u8),
            sender: note.metadata.sender().to_bytes(),
            tag: note.metadata.tag().to_raw_sql(),
            network_note_type: network_note_type.into(),
            target_account_id: target_account_id.map(|t| t.target_id().to_bytes()),
            attachment: attachment_bytes,
            inclusion_path: note.inclusion_path.to_bytes(),
            consumed_at: None::<i64>, // New notes are always unconsumed.
            nullifier: nullifier.as_ref().map(Nullifier::to_bytes),
            assets: note.details.as_ref().map(|d| d.assets().to_bytes()),
            storage: note.details.as_ref().map(|d| d.storage().to_bytes()),
            script_root: note.details.as_ref().map(|d| d.script().root().to_bytes()),
            serial_num: note.details.as_ref().map(|d| d.serial_num().to_bytes()),
        }
    }
}
