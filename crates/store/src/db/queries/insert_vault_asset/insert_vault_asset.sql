-- Inserts a vault asset as the current version of its key, valid from `block_num` onwards. A NULL
-- asset records the removal of that key.
INSERT INTO account_vault_assets (account_id, block_num, vault_key, asset, valid_until)
VALUES (?1, ?2, ?3, ?4, ?5)
