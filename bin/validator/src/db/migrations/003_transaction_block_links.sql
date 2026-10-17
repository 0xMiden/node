-- Records which signed block includes each validated transaction, and at which position.
--
-- A transaction is validated before it is part of any block, so a validated transaction gains a
-- row here only once a signed block includes it. `(block_num, block_tx_index)` is the
-- transaction's position in the chain's committed order.
CREATE TABLE block_transactions (
    -- Height of the signed block. Deleting the block header deletes its links with it.
    block_num      BIGINT NOT NULL REFERENCES block_headers(block_num) ON DELETE CASCADE,
    -- Index of the transaction within the block.
    block_tx_index BIGINT NOT NULL,
    -- The included transaction. A transaction is included by at most one block, and only
    -- transactions validated by this validator can be linked.
    transaction_id BLOB   NOT NULL UNIQUE REFERENCES validated_transactions(id),
    -- Also the index that serves listing in committed order.
    PRIMARY KEY (block_num, block_tx_index)
) WITHOUT ROWID;
