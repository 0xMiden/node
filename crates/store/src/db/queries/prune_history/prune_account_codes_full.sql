-- Deletes account codes that no account row reaching past the retention cutoff still references.
--
-- The full pass, used when no previous cutoff has been recorded (the first prune after migration,
-- or a fresh database). The single `valid_until > ?1` predicate covers rows inside the window, all
-- open-ended (current) rows, and each account's baseline row — the row still valid at the cutoff
-- even though it was written before it.
--
-- The forced `idx_accounts_code_validity` covering index keeps the subquery an index-only range
-- scan, sized by rows valid at or after the cutoff rather than by total history.
DELETE FROM account_codes
WHERE code_commitment NOT IN (
    SELECT DISTINCT code_commitment
    FROM accounts INDEXED BY idx_accounts_code_validity
    WHERE code_commitment IS NOT NULL
      AND valid_until > ?1
)
