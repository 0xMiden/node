CREATE TABLE transactions (
    id         BLOB NOT NULL,
    account_id BLOB NOT NULL,
    summary    BLOB NOT NULL, -- Binary encoded TransactionSummary.
    PRIMARY KEY (id)
) WITHOUT ROWID;

CREATE INDEX idx_transactions_account_id ON transactions(account_id);
