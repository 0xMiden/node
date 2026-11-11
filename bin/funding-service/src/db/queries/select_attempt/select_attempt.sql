SELECT transaction_id, reference_block, expiration_block
FROM transaction_attempt
WHERE singleton = 1;
