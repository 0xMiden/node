-- Returns the notes with the given ids, with their details and script where they are stored.
--
-- The script is in `note_scripts`, keyed by the script root of the note. The join is a left join
-- because private notes store no script.
--
-- Note ids are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT notes.committed_at, notes.batch_index, notes.note_index, notes.note_id, notes.note_type,
       notes.sender, notes.tag, notes.attachment, notes.assets, notes.storage, notes.serial_num,
       notes.inclusion_path, note_scripts.script
FROM notes
LEFT JOIN note_scripts ON notes.script_root = note_scripts.script_root
WHERE notes.note_id IN (SELECT value FROM rarray(?1))
