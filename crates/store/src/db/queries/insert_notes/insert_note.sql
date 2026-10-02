-- Inserts a note committed by a block.
--
-- Public notes carry their nullifier and detail columns (assets, storage, script root, serial
-- number); private notes store NULL for all of them. `consumed_at` is always NULL here: a freshly
-- committed note is unconsumed until a later block's nullifiers mark it.
INSERT INTO notes (
    committed_at,
    batch_index,
    note_index,
    note_id,
    note_type,
    sender,
    tag,
    network_note_type,
    target_account_id,
    attachment,
    inclusion_path,
    consumed_at,
    nullifier,
    assets,
    storage,
    script_root,
    serial_num
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
