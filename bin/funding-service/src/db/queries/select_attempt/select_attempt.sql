SELECT transaction_id, reference_block, expiration_block, deposit_nullifier
FROM transaction_attempt
WHERE singleton = 1;
