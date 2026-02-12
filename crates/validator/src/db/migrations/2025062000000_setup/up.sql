CREATE TABLE validated_transactions (
    id            BLOB NOT NULL,
    block_num     INTEGER NOT NULL,
    account_id    BLOB NOT NULL,
    "transaction" BLOB NOT NULL, -- Binary encoded ExecutedTransaction.
    PRIMARY KEY (id)
) WITHOUT ROWID;

CREATE INDEX idx_validated_transactions_account_id ON validated_transactions(account_id);
CREATE INDEX idx_validated_transactions_block_num ON validated_transactions(block_num);
