-- Returns the chunk of transactions after the `(block_num, transaction_id)` cursor.
--
-- The cursor comparison uses plain parameters and not nullable parameters, so the range scan can
-- use the index on `(block_num, transaction_id)`.
SELECT account_id, block_num, transaction_id, initial_state_commitment, final_state_commitment,
       input_notes, output_notes, size_in_bytes
FROM transactions
WHERE block_num >= ?1
  AND block_num <= ?2
  AND account_id IN (SELECT value FROM rarray(?3))
  AND (block_num > ?5 OR (block_num = ?5 AND transaction_id > ?6))
ORDER BY block_num ASC, transaction_id ASC
LIMIT ?4
