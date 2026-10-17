-- Inserts a storage-map entry as the current version of its key, valid from `block_num` onwards.
INSERT INTO account_storage_map_values (account_id, block_num, slot_name, key, value, valid_until)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
