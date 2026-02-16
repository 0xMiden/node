-- Reverse the cleanup indices migration

DROP INDEX IF EXISTS idx_vault_cleanup;
DROP INDEX IF EXISTS idx_storage_cleanup;
