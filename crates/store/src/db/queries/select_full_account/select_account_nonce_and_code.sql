-- Returns the nonce and code of the given account's latest committed state.
SELECT accounts.nonce, account_codes.code
FROM accounts
INNER JOIN account_codes ON accounts.code_commitment = account_codes.code_commitment
WHERE accounts.account_id = ?1
  AND accounts.valid_until = ?2;
