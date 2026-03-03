CREATE TABLE validated_transactions (
    id                    BLOB NOT NULL,
    block_num             INTEGER NOT NULL,
    account_id            BLOB NOT NULL,
    account_delta         BLOB NOT NULL,
    input_notes           BLOB NOT NULL,
    output_notes          BLOB NOT NULL,
    initial_account_hash  BLOB NOT NULL,
    final_account_hash    BLOB NOT NULL,
    fee                   BLOB NOT NULL,
    PRIMARY KEY (id)
) WITHOUT ROWID;

CREATE INDEX idx_validated_transactions_account_id ON validated_transactions(account_id);
CREATE INDEX idx_validated_transactions_block_num ON validated_transactions(block_num);
