-- Heights imported before this validator signed a block at that height.
ALTER TABLE recovery_confirmation
ADD COLUMN missed_heights INTEGER NOT NULL DEFAULT 0 CHECK (missed_heights >= 0);

-- A recovered block can include transactions that this validator has yet to validate.
CREATE TABLE block_transactions_new (
    block_num BIGINT NOT NULL REFERENCES blocks(block_num) ON DELETE CASCADE,
    block_tx_index BIGINT NOT NULL,
    transaction_id BLOB NOT NULL UNIQUE,
    PRIMARY KEY (block_num, block_tx_index)
) WITHOUT ROWID;

INSERT INTO block_transactions_new (block_num, block_tx_index, transaction_id)
SELECT block_num, block_tx_index, transaction_id FROM block_transactions;

DROP TABLE block_transactions;
ALTER TABLE block_transactions_new RENAME TO block_transactions;
