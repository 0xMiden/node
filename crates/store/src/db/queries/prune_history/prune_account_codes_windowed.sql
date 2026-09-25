-- Deletes account codes that became collectable since the previous prune.
--
-- Candidates are the codes referenced by rows whose validity interval ended inside
-- `(?1, ?2]` — the window between the previous cutoff and this one. A code that survived the
-- previous prune did so because some row with `valid_until > ?1` referenced it; for it to be
-- deletable now, the longest-lived such row must have expired by `?2`, which puts its
-- `valid_until` in exactly that window. The scan is an `idx_accounts_code_validity` index range,
-- so its cost scales with account updates since the previous prune, not with total history.
--
-- Each candidate is then deleted only if the `idx_accounts_code_probe` existence probe finds no
-- row still referencing it past the new cutoff.
DELETE FROM account_codes
WHERE code_commitment IN (
    SELECT DISTINCT code_commitment
    FROM accounts INDEXED BY idx_accounts_code_validity
    WHERE code_commitment IS NOT NULL
      AND valid_until > ?1
      AND valid_until <= ?2
)
AND NOT EXISTS (
    SELECT 1
    FROM accounts INDEXED BY idx_accounts_code_probe
    WHERE accounts.code_commitment = account_codes.code_commitment
      AND accounts.valid_until > ?2
)
