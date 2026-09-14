-- Returns the attempt count and the serialized note for one note.
SELECT attempt_count, note_data FROM notes WHERE nullifier = ?1
