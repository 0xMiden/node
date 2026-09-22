-- Select the oldest notes before deleting them. The cursor breaks timestamp ties.
-- RETURNING reports only the payload sizes of rows that this statement deletes.
DELETE FROM notes
WHERE seq IN (
    SELECT seq FROM notes
    WHERE created_at < ?1
    ORDER BY created_at, seq
    LIMIT ?2
)
RETURNING LENGTH(header) + LENGTH(details);
