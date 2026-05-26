// @generated automatically by Diesel CLI.

diesel::table! {
    account_codes (code_commitment) {
        code_commitment -> Binary,
        code -> Binary,
    }
}

diesel::table! {
    account_storage_map_values (account_id, block_num, slot_name, key) {
        account_id -> Binary,
        block_num -> BigInt,
        slot_name -> Text,
        key -> Binary,
        value -> Binary,
        is_latest -> Bool,
    }
}

diesel::table! {
    account_vault_assets (account_id, block_num, vault_key) {
        account_id -> Binary,
        block_num -> BigInt,
        vault_key -> Binary,
        asset -> Nullable<Binary>,
        is_latest -> Bool,
    }
}

diesel::table! {
    accounts (account_id, block_num) {
        account_id -> Binary,
        network_account_type -> Integer,
        block_num -> BigInt,
        account_commitment -> Binary,
        code_commitment -> Nullable<Binary>,
        nonce -> Nullable<BigInt>,
        storage_header -> Nullable<Binary>,
        vault_root -> Nullable<Binary>,
        is_latest -> Bool,
        created_at_block -> BigInt,
    }
}

diesel::table! {
    block_headers (block_num) {
        block_num -> BigInt,
        block_header -> Binary,
        signature -> Binary,
        commitment -> Binary,
    }
}

diesel::table! {
    note_scripts (script_root) {
        script_root -> Binary,
        script -> Binary,
    }
}

diesel::table! {
    notes (committed_at, batch_index, note_index) {
        committed_at -> BigInt,
        batch_index -> Integer,
        note_index -> Integer,
        details_commitment -> Binary,
        note_id -> Binary,
        note_type -> Integer,
        sender -> Binary,
        tag -> Integer,
        network_note_type -> Integer,
        target_account_id -> Nullable<Binary>,
        attachment -> Binary,
        inclusion_path -> Binary,
        consumed_at -> Nullable<BigInt>,
        nullifier -> Nullable<Binary>,
        assets -> Nullable<Binary>,
        storage -> Nullable<Binary>,
        script_root -> Nullable<Binary>,
        serial_num -> Nullable<Binary>,
    }
}

diesel::table! {
    nullifiers (nullifier) {
        nullifier -> Binary,
        nullifier_prefix -> Integer,
        block_num -> BigInt,
    }
}

diesel::table! {
    transactions (transaction_id) {
        transaction_id -> Binary,
        account_id -> Binary,
        block_num -> BigInt,
        initial_state_commitment -> Binary,
        final_state_commitment -> Binary,
        input_notes -> Binary,
        output_notes -> Binary,
        size_in_bytes -> BigInt,
        fee -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    account_codes,
    account_storage_map_values,
    account_vault_assets,
    accounts,
    block_headers,
    note_scripts,
    notes,
    nullifiers,
    transactions,
);
