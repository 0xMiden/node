CREATE TABLE validated_transactions (
    id                    BLOB NOT NULL,
    block_num             INTEGER NOT NULL,
    account_id            BLOB NOT NULL,
    account_delta         BLOB,
    input_notes           BLOB,
    output_notes          BLOB,
    initial_account_hash  BLOB NOT NULL,
    final_account_hash    BLOB NOT NULL,
    fee                   BLOB NOT NULL,
    PRIMARY KEY (id)
) WITHOUT ROWID;

CREATE INDEX idx_validated_transactions_account_id ON validated_transactions(account_id);
CREATE INDEX idx_validated_transactions_block_num ON validated_transactions(block_num);

CREATE TABLE block_headers (
    block_num    INTEGER PRIMARY KEY,
    block_header BLOB NOT NULL
) WITHOUT ROWID;
