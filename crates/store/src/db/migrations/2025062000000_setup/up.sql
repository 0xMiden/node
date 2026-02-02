CREATE TABLE block_headers (
    block_num    INTEGER NOT NULL,
    block_header BLOB    NOT NULL,
    signature    BLOB    NOT NULL,

    PRIMARY KEY (block_num),
    CONSTRAINT block_header_block_num_is_u32 CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF)
);

CREATE TABLE account_codes (
    code_commitment BLOB NOT NULL,
    code            BLOB NOT NULL,
    PRIMARY KEY(code_commitment)
) WITHOUT ROWID;

CREATE TABLE accounts (
    account_id                              BLOB    NOT NULL,
    network_account_type                    INTEGER NOT NULL, -- 0-not a network account, 1-network account
    block_num                               INTEGER NOT NULL,
    account_commitment                      BLOB    NOT NULL,
    code_commitment                         BLOB,
    nonce                                   INTEGER,
    storage_header                          BLOB,             -- Serialized AccountStorageHeader from miden-objects
    vault_root                              BLOB,             -- Vault root commitment
    is_latest                               BOOLEAN NOT NULL DEFAULT 0, -- Indicates if this is the latest state for this account_id
    created_at_block                        INTEGER NOT NULL,

    PRIMARY KEY (account_id, block_num),
    CONSTRAINT all_null_or_none_null CHECK
        (
            (code_commitment IS NOT NULL AND nonce IS NOT NULL AND storage_header IS NOT NULL AND vault_root IS NOT NULL)
            OR
            (code_commitment IS NULL AND nonce IS NULL AND storage_header IS NULL AND vault_root IS NULL)
        ),
    CONSTRAINT accounts_network_account_type_in_enum CHECK (network_account_type BETWEEN 0 AND 1)
) WITHOUT ROWID;

CREATE INDEX idx_accounts_network_type ON accounts(network_account_type) WHERE network_account_type = 1;
CREATE INDEX idx_accounts_id_block ON accounts(account_id, block_num DESC);
CREATE INDEX idx_accounts_latest ON accounts(account_id, is_latest) WHERE is_latest = 1;
CREATE INDEX idx_accounts_created_at_block ON accounts(created_at_block);
-- Index for joining with block_headers
CREATE INDEX idx_accounts_block_num ON accounts(block_num);
-- Index for joining with account_codes
CREATE INDEX idx_accounts_code_commitment ON accounts(code_commitment) WHERE code_commitment IS NOT NULL;

CREATE TABLE notes (
    committed_at                  INTEGER NOT NULL, -- Block number when the note was committed
    batch_index                   INTEGER NOT NULL, -- Index of batch in block, starting from 0
    note_index                    INTEGER NOT NULL, -- Index of note in batch, starting from 0
    note_id                       BLOB    NOT NULL,
    note_commitment               BLOB    NOT NULL,
    note_type                     INTEGER NOT NULL, -- 1-Public (0b01), 2-Private (0b10), 3-Encrypted (0b11)
    sender                        BLOB    NOT NULL,
    tag                           INTEGER NOT NULL,
    network_note_type             INTEGER NOT NULL, -- 0-not a network note, 1-single account target network note
    target_account_id             BLOB,             -- Full target account ID for single-target network notes
    attachment                    BLOB    NOT NULL, -- Serialized note attachment data
    inclusion_path                BLOB    NOT NULL, -- Serialized sparse Merkle path of the note in the block's note tree
    consumed_at                   INTEGER,          -- Block number when the note was consumed
    nullifier                     BLOB,             -- Only known for public notes, null for private notes
    assets                        BLOB,
    storage                       BLOB,
    script_root                   BLOB,
    serial_num                    BLOB,

    PRIMARY KEY (committed_at, batch_index, note_index),
    CONSTRAINT notes_type_in_enum CHECK (note_type BETWEEN 1 AND 3),
    CONSTRAINT notes_network_note_type_in_enum CHECK (network_note_type BETWEEN 0 AND 1),
    CONSTRAINT notes_consumed_at_is_u32 CHECK (consumed_at BETWEEN 0 AND 0xFFFFFFFF),
    CONSTRAINT notes_batch_index_is_u32 CHECK (batch_index BETWEEN 0 AND 0xFFFFFFFF),
    CONSTRAINT notes_note_index_is_u32 CHECK (note_index BETWEEN 0 AND 0xFFFFFFFF)
);

CREATE INDEX idx_notes_note_id ON notes(note_id);
CREATE INDEX idx_notes_note_commitment ON notes(note_commitment);
CREATE INDEX idx_notes_sender ON notes(sender, committed_at);
CREATE INDEX idx_notes_tag ON notes(tag, committed_at);
CREATE INDEX idx_notes_nullifier ON notes(nullifier);
CREATE INDEX idx_notes_target_account ON notes(target_account_id, committed_at) WHERE target_account_id IS NOT NULL;
-- Index for joining with block_headers on committed_at
CREATE INDEX idx_notes_committed_at ON notes(committed_at);
-- Index for joining with note_scripts
CREATE INDEX idx_notes_script_root ON notes(script_root) WHERE script_root IS NOT NULL;
-- Index for joining with block_headers on consumed_at
CREATE INDEX idx_notes_consumed_at ON notes(consumed_at) WHERE consumed_at IS NOT NULL;

CREATE TABLE note_scripts (
    script_root BLOB NOT NULL,
    script      BLOB NOT NULL,

    PRIMARY KEY (script_root)
) WITHOUT ROWID;

CREATE TABLE account_storage_map_values (
    account_id          BLOB    NOT NULL,
    block_num           INTEGER NOT NULL,
    slot_name           TEXT    NOT NULL,
    key                 BLOB    NOT NULL,
    value               BLOB    NOT NULL,
    is_latest           BOOLEAN NOT NULL,

    PRIMARY KEY (account_id, block_num, slot_name, key),
    FOREIGN KEY (account_id, block_num) REFERENCES accounts(account_id, block_num) ON DELETE CASCADE
) WITHOUT ROWID;

-- Index for joining with accounts table on compound key
CREATE INDEX idx_account_storage_account_block ON account_storage_map_values(account_id, block_num);
-- Index for querying latest values
CREATE INDEX idx_account_storage_latest ON account_storage_map_values(account_id, is_latest) WHERE is_latest = 1;

CREATE TABLE account_vault_assets (
    account_id          BLOB    NOT NULL,
    block_num           INTEGER NOT NULL,
    vault_key           BLOB    NOT NULL,
    asset               BLOB,
    is_latest           BOOLEAN NOT NULL,

    PRIMARY KEY (account_id, block_num, vault_key),
    FOREIGN KEY (account_id, block_num) REFERENCES accounts(account_id, block_num) ON DELETE CASCADE
) WITHOUT ROWID;

-- Index for joining with accounts table on compound key
CREATE INDEX idx_vault_assets_account_block ON account_vault_assets(account_id, block_num);
-- Index for querying latest assets
CREATE INDEX idx_vault_assets_latest ON account_vault_assets(account_id, is_latest) WHERE is_latest = 1;

CREATE TABLE nullifiers (
    nullifier        BLOB    NOT NULL,
    nullifier_prefix INTEGER NOT NULL,
    block_num        INTEGER NOT NULL,

    PRIMARY KEY (nullifier),
    CONSTRAINT nullifiers_nullifier_is_digest CHECK (length(nullifier) = 32),
    CONSTRAINT nullifiers_nullifier_prefix_is_u16 CHECK (nullifier_prefix BETWEEN 0 AND 0xFFFF)
) WITHOUT ROWID;

CREATE INDEX idx_nullifiers_prefix ON nullifiers(nullifier_prefix);
-- Index for joining with block_headers
CREATE INDEX idx_nullifiers_block_num ON nullifiers(block_num);

CREATE TABLE transactions (
    transaction_id               BLOB    NOT NULL,
    account_id                   BLOB    NOT NULL,
    block_num                    INTEGER NOT NULL, -- Block number in which the transaction was included.
    initial_state_commitment     BLOB    NOT NULL, -- State of the account before applying the transaction.
    final_state_commitment       BLOB    NOT NULL, -- State of the account after applying the transaction.
    nullifiers                   BLOB    NOT NULL, -- Serialized vector with the Nullifier of the input notes.
    output_notes                 BLOB    NOT NULL, -- Serialized vector with the NoteId of the output notes.
    size_in_bytes                INTEGER NOT NULL, -- Estimated size of the row in bytes, considering the size of the input and output notes.

    PRIMARY KEY (transaction_id)
) WITHOUT ROWID;

-- Index for joining with accounts (note: account may not exist in accounts table)
CREATE INDEX idx_transactions_account_id ON transactions(account_id);
-- Index for joining with block_headers
CREATE INDEX idx_transactions_block_num ON transactions(block_num);
