-- Singleton row storing the chain tip header.
-- The chain MMR is reconstructed on startup from the store and maintained in memory.
CREATE TABLE chain_state (
    -- Singleton constraint: only one row allowed.
    id              INTEGER PRIMARY KEY CHECK (id = 0),
    -- Block number of the chain tip.
    block_num       INTEGER NOT NULL,
    -- Serialized BlockHeader.
    block_header    BLOB    NOT NULL,

    CONSTRAINT chain_state_block_num_is_u32 CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF)
);

-- One row per network account with its latest committed state.
CREATE TABLE committed_accounts (
    -- AccountId serialized bytes (8 bytes). Primary key.
    account_id      BLOB    PRIMARY KEY,
    -- Serialized Account.
    account_data    BLOB    NOT NULL
) WITHOUT ROWID;

-- Ordered chain of uncommitted account updates per account.
-- The auto-incrementing ID preserves insertion order (equivalent to VecDeque ordering).
CREATE TABLE inflight_account_deltas (
    -- Auto-incrementing ID preserves insertion order.
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- FK to committed_accounts. May be NULL for accounts created by inflight txs.
    account_id      BLOB    NOT NULL,
    -- The transaction that produced this delta.
    transaction_id  BLOB    NOT NULL,
    -- Serialized Account state after applying this delta.
    account_data    BLOB    NOT NULL
);

CREATE INDEX idx_inflight_deltas_account ON inflight_account_deltas(account_id);

-- Unconsumed notes from committed blocks, keyed by nullifier.
CREATE TABLE committed_notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- FK to the target account.
    account_id      BLOB    NOT NULL,
    -- Serialized SingleTargetNetworkNote (protobuf bytes).
    note_data       BLOB    NOT NULL,
    -- Backoff tracking: number of failed execution attempts.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    -- Backoff tracking: block number of the last failed attempt. NULL if never attempted.
    last_attempt    INTEGER,

    CONSTRAINT committed_notes_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT committed_notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_committed_notes_account ON committed_notes(account_id);

-- Notes created by inflight transactions (not yet committed).
CREATE TABLE inflight_notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- FK to the target account.
    account_id      BLOB    NOT NULL,
    -- The transaction that created this note.
    transaction_id  BLOB    NOT NULL,
    -- Serialized SingleTargetNetworkNote (protobuf bytes).
    note_data       BLOB    NOT NULL,
    -- Backoff tracking.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_attempt    INTEGER,

    CONSTRAINT inflight_notes_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT inflight_notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_inflight_notes_account ON inflight_notes(account_id);
CREATE INDEX idx_inflight_notes_tx ON inflight_notes(transaction_id);

-- Notes consumed by inflight transactions (pending confirmation).
-- Replaces the `nullified` HashMap in NotePool.
CREATE TABLE inflight_nullifiers (
    -- Nullifier of the consumed note.
    nullifier       BLOB    PRIMARY KEY,
    -- FK to the target account.
    account_id      BLOB    NOT NULL,
    -- The transaction that consumed this note.
    transaction_id  BLOB    NOT NULL,
    -- Serialized note data, preserved for revert.
    note_data       BLOB    NOT NULL,
    -- Backoff tracking preserved from the note.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_attempt    INTEGER,

    CONSTRAINT inflight_nullifiers_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT inflight_nullifiers_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_inflight_nullifiers_account ON inflight_nullifiers(account_id);
CREATE INDEX idx_inflight_nullifiers_tx ON inflight_nullifiers(transaction_id);

-- Tracks which transactions are uncommitted, linking to their effects.
CREATE TABLE inflight_transactions (
    -- TransactionId bytes (32 bytes). Primary key.
    transaction_id      BLOB    PRIMARY KEY,
    -- The account this transaction impacts. NULL if no account delta.
    delta_account_id    BLOB
) WITHOUT ROWID;

-- Events cached for network accounts that haven't been spawned yet.
CREATE TABLE predating_events (
    -- Composite primary key.
    account_id      BLOB    NOT NULL,
    transaction_id  BLOB    NOT NULL,
    -- Serialized MempoolEvent (protobuf bytes).
    event_data      BLOB    NOT NULL,

    PRIMARY KEY (account_id, transaction_id)
) WITHOUT ROWID;
