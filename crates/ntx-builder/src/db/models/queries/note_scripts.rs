//! Database queries for persisting and retrieving note scripts.

use diesel::prelude::*;
use miden_protocol::Word;
use miden_protocol::note::NoteScript;

use crate::db::errors::DatabaseError;
use crate::db::models::conv as conversions;
use crate::db::schema;

#[derive(Insertable)]
#[diesel(table_name = schema::note_scripts)]
struct NoteScriptInsert {
    script_root: Vec<u8>,
    script_data: Vec<u8>,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::note_scripts)]
struct NoteScriptRow {
    script_data: Vec<u8>,
}

/// Looks up a note script by its root hash.
pub fn lookup_note_script(
    conn: &mut SqliteConnection,
    script_root: &Word,
) -> Result<Option<NoteScript>, DatabaseError> {
    let root_bytes = conversions::word_to_bytes(script_root);

    let row: Option<NoteScriptRow> = schema::note_scripts::table
        .find(root_bytes)
        .select(NoteScriptRow::as_select())
        .first(conn)
        .optional()?;

    row.map(|r| conversions::note_script_from_bytes(&r.script_data)).transpose()
}

/// Inserts a note script (idempotent via INSERT OR IGNORE).
pub fn insert_note_script(
    conn: &mut SqliteConnection,
    script_root: &Word,
    script: &NoteScript,
) -> Result<(), DatabaseError> {
    let insert = NoteScriptInsert {
        script_root: conversions::word_to_bytes(script_root),
        script_data: conversions::note_script_to_bytes(script),
    };

    diesel::insert_or_ignore_into(schema::note_scripts::table)
        .values(&insert)
        .execute(conn)?;

    Ok(())
}
