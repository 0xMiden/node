WITH candidates AS (
    SELECT seq, LENGTH(header) + LENGTH(details) AS bytes
    FROM notes
    WHERE seq > ?1 AND tag IN (SELECT value FROM rarray(?2))
    ORDER BY seq
    LIMIT ?3
), bounded AS (
    SELECT
        seq,
        SUM(bytes) OVER (ORDER BY seq) AS running_bytes,
        COUNT(*) OVER () AS candidate_count
    FROM candidates
)
SELECT
    notes.seq,
    notes.header,
    notes.details,
    notes.created_at,
    notes.after_block_num,
    bounded.candidate_count
FROM bounded
JOIN notes ON notes.seq = bounded.seq
WHERE bounded.running_bytes <= ?4
ORDER BY notes.seq
LIMIT ?5;
