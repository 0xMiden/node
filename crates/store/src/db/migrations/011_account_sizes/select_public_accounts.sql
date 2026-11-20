SELECT account_id, block_num, storage_header
FROM accounts
WHERE storage_header IS NOT NULL
