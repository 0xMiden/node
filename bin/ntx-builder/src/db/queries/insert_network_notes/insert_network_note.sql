-- Inserts a network note from a committed block. Uses `INSERT OR IGNORE` so re-applying the same
-- block (e.g. on a redelivery from the subscription stream) is a no-op rather than a constraint
-- violation. `attempt_count` defaults to 0 and the remaining backoff/lifecycle columns default to
-- NULL.
--
-- `next_eligible_block` is the first block at which the note's execution hint permits consumption.
-- A note that has never been attempted has no backoff, so the hint is the only delay.
INSERT OR IGNORE INTO notes (nullifier, account_id, note_data, note_id, next_eligible_block)
VALUES (?1, ?2, ?3, ?4, ?5)
