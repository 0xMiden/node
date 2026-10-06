-- Returns the chunk of transactions after the `(block_num, transaction_id)` cursor.
--
-- The cursor supplies the lower range bound. The caller checks the requested range before selection.
SELECT account_id, block_num, transaction_id, initial_state_commitment, final_state_commitment,
       input_notes, output_notes, size_in_bytes
FROM transactions
WHERE block_num <= ?1
  AND account_id IN (SELECT value FROM rarray(?2))
  AND (block_num, transaction_id) > (?4, ?5)
ORDER BY block_num ASC, transaction_id ASC
LIMIT ?3
