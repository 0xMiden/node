-- Singleton row storing the chain tip header and the partial chain MMR.
--
-- The MMR is persisted so the ntx-builder can resume from its committed chain state on restart
-- without having to replay the full block subscription from genesis.
CREATE TABLE chain_state (
    -- Singleton constraint: only one row allowed.
    id              INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
    -- Block number of the chain tip.
    block_num       BIGINT  NOT NULL,
    -- Serialized BlockHeader.
    block_header    BLOB    NOT NULL,
    -- Serialized PartialMmr corresponding to `block_header`.
    chain_mmr       BLOB    NOT NULL,
    -- Serialized genesis block commitment (Word). Set once at bootstrap and retained across tip
    -- updates; used for the `genesis` Accept-header param required by write RPCs.
    genesis_commitment BLOB NOT NULL,

    CONSTRAINT chain_state_block_num_is_u32 CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF)
);

-- Committed network accounts, keyed by account ID.
--
-- The ntx-builder derives all account state from the committed block stream, so we only ever
-- store the latest committed account row per account.
CREATE TABLE accounts (
    -- AccountId serialized bytes (8 bytes).
    account_id      BLOB    NOT NULL PRIMARY KEY,
    -- Serialized Account state.
    account_data    BLOB    NOT NULL,
    -- TransactionId (32 bytes) of the latest transaction that updated this account in a committed
    -- block. Always set: an account row is created from the block that created the account, whose
    -- creation transaction is the first value here. Actors compare their own submitted tx id
    -- against this to confirm landing without an RPC roundtrip.
    last_tx_id      BLOB    NOT NULL
) WITHOUT ROWID;

-- Network notes targeting network accounts, plus backoff metadata used by the actor execution
-- path that consumes them in subsequent PRs.
--
-- A row is inserted when the note appears in a committed block. When the note's nullifier later
-- appears in a committed block, `committed_at` is set to that block number rather than deleting
-- the row. This lets the `GetNetworkNoteStatus` endpoint surface the full lifecycle (pending,
-- consumed, discarded) for any note the ntx-builder has ever seen.
CREATE TABLE notes (
    -- Nullifier bytes (32 bytes). Primary key.
    nullifier       BLOB    PRIMARY KEY,
    -- Target account ID.
    account_id      BLOB    NOT NULL,
    -- Serialized AccountTargetNetworkNote.
    note_data       BLOB    NOT NULL,
    -- Note ID bytes.
    note_id         BLOB,
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

-- Partial index covers the actor's hot path (`account_id = ? AND committed_at IS NULL`).
CREATE INDEX idx_notes_account_pending ON notes(account_id) WHERE committed_at IS NULL;
CREATE INDEX idx_notes_note_id ON notes(note_id) WHERE note_id IS NOT NULL;

-- Persistent cache of note scripts, keyed by script root hash.
-- Survives restarts so scripts don't need to be re-fetched from the store.
CREATE TABLE note_scripts (
    -- Script root hash (Word serialized to 32 bytes).
    script_root BLOB PRIMARY KEY,
    -- Serialized NoteScript bytes.
    script_data BLOB NOT NULL
) WITHOUT ROWID;
