ALTER TABLE transactions ADD COLUMN transaction_index INTEGER NOT NULL CHECK (transaction_index >= 0);
ALTER TABLE transactions ADD COLUMN public_log_count INTEGER CHECK (public_log_count BETWEEN 0 AND 64);

CREATE UNIQUE INDEX idx_transactions_block_position ON transactions(block_num, transaction_index);

CREATE TABLE transaction_logs (
    native_account_id BLOB NOT NULL,
    block_num INTEGER NOT NULL CHECK (block_num >= 0),
    transaction_index INTEGER NOT NULL CHECK (transaction_index >= 0),
    log_index INTEGER NOT NULL CHECK (log_index BETWEEN 0 AND 63),
    transaction_id BLOB NOT NULL REFERENCES transactions(transaction_id),
    emitter BLOB NOT NULL,
    topic BLOB NOT NULL CHECK (length(topic) = 16),
    content BLOB NOT NULL CHECK (length(content) <= 2048 AND length(content) % 32 = 0),
    PRIMARY KEY (native_account_id, block_num, transaction_index, log_index)
) WITHOUT ROWID;

CREATE INDEX idx_transaction_logs_account_topic_position
    ON transaction_logs(native_account_id, topic, block_num, transaction_index, log_index);
