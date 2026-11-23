-- Deletes the FEE_SPONSORSHIP notes whose nullifier was committed before block ?1, oldest first,
-- up to ?2 rows. Unconsumed sponsorships have no `committed_at` and are kept.
DELETE FROM sponsorship_notes
WHERE nullifier IN (
    SELECT nullifier FROM sponsorship_notes
    WHERE committed_at < ?1
    ORDER BY committed_at
    LIMIT ?2
)
