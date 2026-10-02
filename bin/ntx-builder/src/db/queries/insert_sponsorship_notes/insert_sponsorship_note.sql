-- Inserts a FEE_SPONSORSHIP note from a committed block. Uses `INSERT OR IGNORE` so re-applying
-- the same block (e.g. on a redelivery from the subscription stream) is a no-op rather than a
-- constraint violation. `committed_at` defaults to NULL (pending consumption).
INSERT OR IGNORE INTO sponsorship_notes (nullifier, note_id, feature_note_id, note_data, reclaim_height)
VALUES (?1, ?2, ?3, ?4, ?5)
