CREATE TABLE validated_transactions (
    id         BLOB NOT NULL,
    account_id BLOB NOT NULL,
    info       BLOB NOT NULL, -- Binary encoded ValidatedTransactionInfo.
    PRIMARY KEY (id)
) WITHOUT ROWID;

CREATE INDEX idx__validated_transactions_account_id ON validated_transactions(account_id);
