-- Materializes note eligibility so the scheduler can ask for the ready accounts.
ALTER TABLE notes ADD COLUMN next_eligible_block BIGINT NOT NULL DEFAULT 0
    CHECK (next_eligible_block BETWEEN 0 AND 0xFFFFFFFF);

-- Replaces the account-only partial index with one that also covers the eligibility filter and the
-- attempt budget, so the ready-accounts query is answered from the index.
DROP INDEX idx_notes_account_pending;
CREATE INDEX idx_notes_account_pending
    ON notes(account_id, next_eligible_block, attempt_count)
    WHERE committed_at IS NULL;
