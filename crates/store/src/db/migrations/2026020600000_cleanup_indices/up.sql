-- Add indices to optimize cleanup queries that delete old non-latest entries.
--
-- These partial indices only include rows where is_latest = 0, making them:
-- - Smaller (only index rows that will eventually be deleted)
-- - Faster for cleanup operations (direct lookup of old entries)
-- - No overhead for is_latest = 1 rows (which are never deleted)

CREATE INDEX idx_vault_cleanup ON account_vault_assets(block_num) WHERE is_latest = 0;
CREATE INDEX idx_storage_cleanup ON account_storage_map_values(block_num) WHERE is_latest = 0;
