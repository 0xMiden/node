-- Returns the account code stored under the given commitment.
SELECT code
FROM account_codes
WHERE code_commitment = ?1
