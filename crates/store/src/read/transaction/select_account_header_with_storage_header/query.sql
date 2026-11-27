-- Returns the columns making up the given account's header as of a block.
--
-- The most recent row at or before the block holds the state in force then.
SELECT code_commitment, nonce, storage_header, vault_root
FROM accounts
WHERE account_id = ?1
  AND block_num <= ?2
ORDER BY block_num DESC
LIMIT 1;
