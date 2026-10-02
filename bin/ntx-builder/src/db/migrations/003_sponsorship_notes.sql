-- Rebuild `notes` to make `note_id` NOT NULL. Every insert has populated `note_id` since the
-- column was introduced, so the copy is total; SQLite requires a full table rebuild to add the
-- constraint. The `INSERT ... SELECT` fails loudly if a NULL row exists, rather than silently
-- dropping it.
CREATE TABLE notes_new (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- Target account ID.
    account_id      BLOB    NOT NULL,
    -- Serialized AccountTargetNetworkNote.
    note_data       BLOB    NOT NULL,
    -- Note ID bytes.
    note_id         BLOB    NOT NULL,
    -- Backoff tracking: number of failed execution attempts.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    -- Backoff tracking: block number of the last failed attempt. NULL if never attempted.
    last_attempt    BIGINT,
    -- Latest execution error message. NULL if no error recorded.
    last_error      TEXT,
    -- Block number in which the note's nullifier was observed in a committed block. NULL while
    -- the note is still pending consumption.
    committed_at    BIGINT,

    CONSTRAINT notes_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF),
    CONSTRAINT notes_committed_at_is_u32 CHECK (committed_at BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

INSERT INTO notes_new
    (nullifier, account_id, note_data, note_id, attempt_count, last_attempt, last_error,
     committed_at)
SELECT nullifier, account_id, note_data, note_id, attempt_count, last_attempt, last_error,
       committed_at
FROM notes;

DROP TABLE notes;
ALTER TABLE notes_new RENAME TO notes;

-- Partial index covers the actor's hot path (`account_id = ? AND committed_at IS NULL`).
CREATE INDEX idx_notes_account_pending ON notes(account_id) WHERE committed_at IS NULL;
-- `note_id` is NOT NULL now, so the old `WHERE note_id IS NOT NULL` predicate is dropped.
CREATE INDEX idx_notes_note_id ON notes(note_id);

-- FEE_SPONSORSHIP notes, indexed by the feature note they pay the fee for.
--
-- Sponsorship notes have no backoff lifecycle of their own: execution failures are attributed to
-- the feature note, whose row in `notes` carries the attempt tracking.
CREATE TABLE sponsorship_notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- Note ID bytes.
    note_id         BLOB    NOT NULL,
    -- Note ID of the feature note this sponsorship pays for. Joins against `notes.note_id`.
    feature_note_id BLOB    NOT NULL,
    -- Serialized Note.
    note_data       BLOB    NOT NULL,
    -- Block height at or after which the reclaimer may reclaim the note. NULL when reclaim is
    -- disabled.
    reclaim_height  BIGINT,
    -- Block number in which the note's nullifier was observed in a committed block. NULL while
    -- the note is still pending consumption.
    committed_at    BIGINT,

    CONSTRAINT sponsorship_notes_reclaim_height_is_u32
        CHECK (reclaim_height BETWEEN 0 AND 0xFFFFFFFF),
    CONSTRAINT sponsorship_notes_committed_at_is_u32
        CHECK (committed_at BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

-- Partial index covering the selection-time join (`feature_note_id = ? AND committed_at IS NULL`).
CREATE INDEX idx_sponsorship_notes_feature ON sponsorship_notes(feature_note_id)
    WHERE committed_at IS NULL;
