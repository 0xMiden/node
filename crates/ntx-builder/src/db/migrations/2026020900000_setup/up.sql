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

-- Account states: both committed and inflight.
-- Committed rows have transaction_id = NULL. Inflight rows have transaction_id set.
-- The auto-incrementing order_id preserves insertion order (VecDeque semantics).
CREATE TABLE accounts (
    -- Auto-incrementing ID preserves insertion order.
    order_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    -- AccountId serialized bytes (8 bytes).
    account_id      BLOB    NOT NULL,
    -- Serialized Account state.
    account_data    BLOB    NOT NULL,
    -- NULL if this is the committed state; transaction ID if inflight.
    transaction_id  BLOB
);

-- At most one committed row per account.
CREATE UNIQUE INDEX idx_accounts_committed ON accounts(account_id) WHERE transaction_id IS NULL;
-- At most one inflight row per (account, transaction) pair.
CREATE UNIQUE INDEX idx_accounts_inflight ON accounts(account_id, transaction_id)
    WHERE transaction_id IS NOT NULL;
CREATE INDEX idx_accounts_account ON accounts(account_id);
CREATE INDEX idx_accounts_tx ON accounts(transaction_id) WHERE transaction_id IS NOT NULL;

-- Notes: committed, inflight, and nullified — all in one table.
-- created_by = NULL means committed note; non-NULL means created by inflight tx.
-- consumed_by = NULL means unconsumed; non-NULL means consumed by inflight tx.
-- Row is deleted once consumption is committed.
CREATE TABLE notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- Target account ID.
    account_id      BLOB    NOT NULL,
    -- Serialized SingleTargetNetworkNote.
    note_data       BLOB    NOT NULL,
    -- Backoff tracking: number of failed execution attempts.
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    -- Backoff tracking: block number of the last failed attempt. NULL if never attempted.
    last_attempt    INTEGER,
    -- NULL if the note came from a committed block; transaction ID if created by inflight tx.
    created_by      BLOB,
    -- NULL if unconsumed; transaction ID of the consuming inflight tx.
    consumed_by     BLOB,

    CONSTRAINT notes_attempt_count_non_negative CHECK (attempt_count >= 0),
    CONSTRAINT notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_notes_account ON notes(account_id);
CREATE INDEX idx_notes_created_by ON notes(created_by) WHERE created_by IS NOT NULL;
CREATE INDEX idx_notes_consumed_by ON notes(consumed_by) WHERE consumed_by IS NOT NULL;
