SELECT seq, LENGTH(header) + LENGTH(details)
FROM notes
WHERE created_at < ?1
ORDER BY seq
LIMIT ?2;
