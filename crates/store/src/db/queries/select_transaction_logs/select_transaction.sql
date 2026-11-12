SELECT block_num, transaction_index, public_log_count, logs_commitment
FROM transactions
WHERE transaction_id = ?1 AND account_id = ?2 AND block_num <= ?3
