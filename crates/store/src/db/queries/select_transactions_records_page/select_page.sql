-- Returns a chunk of transactions of the given accounts within a block range, in a stable order.
--
-- Account ids are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT transaction_id, block_num, size_in_bytes
FROM transactions
WHERE block_num >= ?1
  AND block_num <= ?2
  AND account_id IN (SELECT value FROM rarray(?3))
ORDER BY block_num ASC, transaction_id ASC
LIMIT ?4
