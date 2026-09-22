-- Parameters:
-- ?1 is the exclusive cursor.
-- ?2 contains the requested tags.
-- ?3 is the row limit plus one. The extra candidate detects another page.
-- ?4 is the payload byte limit.
-- ?5 is the returned row limit.
WITH candidates AS (
    -- First, we select candidates that match tags and are after the cursor.
    -- We're fetching one extra row so that callers can detect if there are
    -- more pages to fetch.
    -- Note that we're not returning the actual data here, as that's not required
    -- for computing cumulative sizes.
    SELECT seq, LENGTH(header) + LENGTH(details) AS bytes
    FROM notes
    WHERE seq > ?1 AND tag IN (SELECT value FROM rarray(?2))
    ORDER BY seq
    LIMIT ?3
), bounded AS (
    -- Then we compute a running sum of the length of the note data.
    SELECT
        seq,
        SUM(bytes) OVER (ORDER BY seq) AS running_bytes,
        COUNT(*) OVER () AS candidate_count
    FROM candidates
)
-- Select candidates that fit into both the payload byte limit and the returned
-- row limit. Note that we return the candidate count which includes the extra
-- row fetched so that callers can see that there are more pages to fetch.
SELECT
    notes.seq,
    notes.header,
    notes.details,
    notes.created_at,
    notes.after_block_num,
    notes.committed_in_block,
    bounded.candidate_count
FROM bounded
JOIN notes ON notes.seq = bounded.seq
WHERE bounded.running_bytes <= ?4
ORDER BY notes.seq
LIMIT ?5;
