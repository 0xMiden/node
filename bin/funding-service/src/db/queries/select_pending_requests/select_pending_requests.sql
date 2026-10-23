SELECT sequence, note, accepted_at, transaction_id, committed_in_block, confirmed_at
FROM requests
WHERE transaction_id IS NULL AND attempt_id IS NULL
ORDER BY sequence
LIMIT ?1;
