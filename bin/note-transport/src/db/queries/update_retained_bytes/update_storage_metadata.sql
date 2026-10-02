UPDATE storage_metadata
SET retained_bytes = ?1
WHERE singleton = 1;
