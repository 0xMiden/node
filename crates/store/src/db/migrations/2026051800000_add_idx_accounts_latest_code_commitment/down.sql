DROP INDEX IF EXISTS idx_accounts_latest_code_commitment;
DROP INDEX IF EXISTS idx_accounts_prune_code;

CREATE INDEX idx_accounts_prune_code
    ON accounts(block_num, is_latest, code_commitment)
    WHERE code_commitment IS NOT NULL;
