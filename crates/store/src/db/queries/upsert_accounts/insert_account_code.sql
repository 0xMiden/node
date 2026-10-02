-- Stores an account's code, keyed by its commitment. Code is shared across accounts and across an
-- account's versions, so a commitment already present is left untouched.
INSERT INTO account_codes (code_commitment, code)
VALUES (?1, ?2)
ON CONFLICT(code_commitment) DO NOTHING
