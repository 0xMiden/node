-- Marks FEE_SPONSORSHIP notes as consumed by setting `committed_at` to the block number whose
-- committed body contained their nullifiers. This covers both consumption alongside the feature
-- note and an external reclaim. Nullifiers we never inserted are silently skipped (no match). Rows
-- are kept around (not deleted), mirroring the `notes` table lifecycle.
UPDATE sponsorship_notes
SET committed_at = ?2
WHERE nullifier IN (SELECT value FROM rarray(?1)) AND committed_at IS NULL
