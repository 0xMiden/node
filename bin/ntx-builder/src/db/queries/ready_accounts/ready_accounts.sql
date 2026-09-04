-- Selects the network accounts that are ready for a transaction attempt: accounts whose creation
-- is committed and which have at least one pending note (unconsumed, within the per-note attempt
-- budget, and past its stored eligibility block).

SELECT n.account_id
FROM notes n
JOIN accounts a ON a.account_id = n.account_id
WHERE n.committed_at IS NULL
  AND n.attempt_count < ?1
  AND n.next_eligible_block <= ?2
  AND n.account_id NOT IN (SELECT value FROM rarray(?3))
GROUP BY n.account_id
ORDER BY MIN(n.next_eligible_block) ASC
LIMIT ?4
