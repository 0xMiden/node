SELECT transaction_id, block_num, size_in_bytes
FROM transactions
WHERE transaction_id IN (SELECT value FROM rarray(?1)) AND block_num <= ?2
  AND transaction_id > ?3
ORDER BY transaction_id
LIMIT ?4
