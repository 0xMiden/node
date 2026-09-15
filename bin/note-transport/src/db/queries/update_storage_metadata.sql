UPDATE storage_metadata
SET next_cursor = ?1, retained_bytes = ?2
WHERE singleton = 1;
