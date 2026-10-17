-- Returns which of the given accounts are network accounts in their latest committed state.
--
-- Account ids are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT account_id
FROM accounts
WHERE account_id IN (SELECT value FROM rarray(?1))
  AND network_account_type = ?2
  AND valid_until = ?3;
