-- Loads note contents only for transactions selected by the metadata page's byte budget.
SELECT account_id, block_num, transaction_id, initial_state_commitment, final_state_commitment,
       input_notes, output_notes, size_in_bytes
FROM transactions
WHERE transaction_id IN (SELECT value FROM rarray(?1))
ORDER BY transaction_id
