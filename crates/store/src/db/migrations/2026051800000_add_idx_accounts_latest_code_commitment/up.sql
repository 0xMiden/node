-- Backfill/reshape the recent-history covering index for prune_account_codes. The old definition
-- included is_latest, but the split recent-history branch only filters by block_num and projects
-- code_commitment.
DROP INDEX IF EXISTS idx_accounts_prune_code;
CREATE INDEX idx_accounts_prune_code
    ON accounts(block_num, code_commitment)
    WHERE code_commitment IS NOT NULL;

-- Covering partial index for prune_account_codes.
--
-- prune_account_codes keeps account code rows that are referenced either by recent account history
-- or by the latest account state. The recent-history branch is covered by idx_accounts_prune_code.
-- This index covers the latest-state branch without scanning historical public account rows.
CREATE INDEX idx_accounts_latest_code_commitment
    ON accounts(code_commitment)
    WHERE is_latest = 1 AND code_commitment IS NOT NULL;
