-- Records the block in which each network note was first observed (i.e. persisted) so the event
-- loop can expire notes that have been pending for too many blocks.
--
-- Without this bound, notes targeting accounts that are never created as network accounts (e.g. an
-- attacker committing notes to arbitrary public account IDs) would accumulate forever, since rows
-- are only ever marked consumed, never deleted.
--
-- Existing rows default to 0xFFFFFFFF (the maximum block number) so that notes persisted before this
-- migration are treated as freshly received and are never age-expired; they still leave the table
-- normally once consumed.
ALTER TABLE notes
    ADD COLUMN received_at_block BIGINT NOT NULL DEFAULT 0xFFFFFFFF
    CHECK (received_at_block BETWEEN 0 AND 0xFFFFFFFF);

-- Covers the age-expiry sweep (`committed_at IS NULL AND received_at_block < ?`).
CREATE INDEX idx_notes_pending_received ON notes(received_at_block) WHERE committed_at IS NULL;
