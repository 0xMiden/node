-- Singleton row storing the chain tip header and partial MMR.
-- Both are populated by replaying committed blocks; on restart the row is loaded so the
-- subscription can resume at `block_num + 1` without re-fetching anything from the store.
CREATE TABLE chain_state (
    -- Singleton constraint: only one row allowed.
    id              INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    -- Block number of the chain tip.
    block_num       INTEGER NOT NULL,
    -- Serialized BlockHeader.
    block_header    BLOB    NOT NULL,
    -- Serialized PartialMmr representing the chain MMR at this tip.
    chain_mmr       BLOB    NOT NULL,

    CONSTRAINT chain_state_block_num_is_u32 CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF)
);

-- Network account states, one row per network account.
CREATE TABLE accounts (
    -- AccountId serialized bytes (8 bytes).
    account_id      BLOB    PRIMARY KEY,
    -- Serialized Account state.
    account_data    BLOB    NOT NULL
) WITHOUT ROWID;

-- Network notes received from committed blocks, keyed by nullifier.
CREATE TABLE notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- Target account ID.
    account_id      BLOB    NOT NULL,
    -- Serialized SingleTargetNetworkNote.
    note_data       BLOB    NOT NULL,
    -- Note ID bytes.
    note_id         BLOB,
    -- Backoff tracking: number of failed execution attempts.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    -- Backoff tracking: block number of the last failed attempt. NULL if never attempted.
    last_attempt    INTEGER,
    -- Latest execution error message. NULL if no error recorded.
    last_error      TEXT,
    -- Block number at which the note's consuming transaction was committed.
    -- NULL while the note is still pending; set on block commit.
    committed_at    INTEGER,

    CONSTRAINT notes_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF),
    CONSTRAINT notes_committed_at_is_u32 CHECK (committed_at BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_notes_account ON notes(account_id);
CREATE INDEX idx_notes_note_id ON notes(note_id) WHERE note_id IS NOT NULL;

-- Persistent cache of note scripts, keyed by script root hash.
-- Survives restarts so scripts don't need to be re-fetched from the store.
CREATE TABLE note_scripts (
    -- Script root hash (Word serialized to 32 bytes).
    script_root BLOB PRIMARY KEY,
    -- Serialized NoteScript bytes.
    script_data BLOB NOT NULL
) WITHOUT ROWID;
