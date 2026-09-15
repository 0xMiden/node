SELECT next_cursor, retained_bytes
FROM storage_metadata
WHERE singleton = 1;
