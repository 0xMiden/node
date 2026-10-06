-- Returns the nullifiers whose prefix is in the requested set and that were created within the
-- given block range, oldest first.
--
-- Prefixes are bound as a single array parameter so the statement text stays constant regardless of
-- how many are requested; see `miden_node_db::sqlite::InList`.
SELECT nullifier, block_num
FROM nullifiers
WHERE nullifier_prefix IN (SELECT value FROM rarray(?1))
  AND block_num >= ?2
  AND block_num <= ?3
ORDER BY block_num ASC
LIMIT ?4
