SELECT next_cursor, retained_bytes, nonce
FROM storage_metadata
WHERE singleton = 1;
