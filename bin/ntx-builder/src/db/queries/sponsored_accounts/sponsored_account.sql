-- Resolves, in one query, the accounts targeted by the still-unconsumed feature notes that the
-- supplied FEE_SPONSORSHIP notes are bound to. Joining against rarray preserves duplicate feature
-- IDs, so the result still contains one account occurrence per sponsorship.
SELECT feature.account_id
FROM rarray(?1) AS sponsored
JOIN notes AS feature ON feature.note_id = sponsored.value
WHERE feature.committed_at IS NULL
