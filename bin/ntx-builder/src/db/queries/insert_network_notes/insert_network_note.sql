-- Inserts a network note. `attempt_count` defaults to 0 and the remaining backoff/lifecycle
-- columns default to NULL.
INSERT INTO notes (nullifier, account_id, note_data, note_id, next_eligible_block)
VALUES (?1, ?2, ?3, ?4, ?5)
