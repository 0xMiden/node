-- Composite index to speed up select_transactions_records.
--
-- The query filters by account_id (IN), block_num range, and paginates via a
-- (block_num, transaction_id) cursor, then orders by (block_num, transaction_id).
-- The existing idx_transactions_account_id index only covers account_id, forcing
-- a full scan over matching rows to apply the block_num filter and sort.
--
-- With (account_id, block_num, transaction_id) SQLite can:
--   1. Seek to each account_id bucket directly,
--   2. Range-scan block_num within that bucket, and
--   3. Use transaction_id for cursor comparison and ORDER BY — all index-only.
CREATE INDEX idx_transactions_account_block_txid
    ON transactions(account_id, block_num, transaction_id);
