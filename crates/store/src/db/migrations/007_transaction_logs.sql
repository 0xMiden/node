ALTER TABLE transactions ADD COLUMN logs_commitment BLOB NOT NULL
    DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (length(logs_commitment) = 32);

CREATE TABLE account_logs (
    emitter_account_id BLOB NOT NULL CHECK (length(emitter_account_id) = 15),
    block_num BIGINT NOT NULL CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF),
    transaction_index BIGINT NOT NULL CHECK (transaction_index BETWEEN 0 AND 65535),
    log_index BIGINT NOT NULL CHECK (log_index BETWEEN 0 AND 63),
    topic BLOB NOT NULL CHECK (length(topic) = 16),
    native_account_id BLOB NOT NULL CHECK (length(native_account_id) = 15),
    transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 32),
    record BLOB NOT NULL CHECK (length(record) <= 8258),
    PRIMARY KEY (emitter_account_id, block_num, transaction_index, log_index),
    FOREIGN KEY (block_num) REFERENCES block_headers(block_num),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
) WITHOUT ROWID;

CREATE INDEX account_logs_topic ON account_logs
    (emitter_account_id, topic, block_num, transaction_index, log_index);
