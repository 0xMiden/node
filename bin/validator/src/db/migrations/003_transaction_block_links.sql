-- Links validated transactions to the signed block that includes them.
--
-- Both columns are nullable by design, not just for legacy rows: records are written at
-- validation time, before the transaction is part of any block. A row stays unlinked while the
-- transaction is in flight, if it is never included in a signed block, or if it predates this
-- migration. Unlinked rows are reachable by transaction id and count towards share issuance, but
-- are never listed: only the committed order (block number, then index within the block) has any
-- bearing on the chain, and an unlinked row has no position in it.
--
-- These columns supersede `insertion_sequence` as the administration API's ordering; that column
-- remains the table's primary key and nothing more.
ALTER TABLE validated_transactions ADD COLUMN block_num BIGINT;
ALTER TABLE validated_transactions ADD COLUMN block_tx_index BIGINT;

-- Serves keyset pagination and block-range filtering in committed order. Partial, because
-- listing never reads unlinked rows.
CREATE INDEX idx_validated_transactions_block_position
ON validated_transactions(block_num, block_tx_index)
WHERE block_num IS NOT NULL;
