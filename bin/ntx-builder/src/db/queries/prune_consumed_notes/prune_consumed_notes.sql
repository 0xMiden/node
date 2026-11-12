-- Deletes the notes whose nullifier was committed before block ?1, oldest first, up to ?2 rows.
-- Pending and discarded notes have no `committed_at` and are kept.
DELETE FROM notes
WHERE nullifier IN (
    SELECT nullifier FROM notes
    WHERE committed_at < ?1
    ORDER BY committed_at
    LIMIT ?2
)
