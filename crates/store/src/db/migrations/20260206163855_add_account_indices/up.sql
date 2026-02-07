CREATE INDEX idx_account_storage_map_latest_by_account_slot_key ON account_storage_map_values(account_id, slot_name, key, is_latest) WHERE is_latest = 1;
CREATE INDEX idx_account_vault_assets_latest_by_account_key ON account_vault_assets(account_id, vault_key, is_latest) WHERE is_latest = 1;
