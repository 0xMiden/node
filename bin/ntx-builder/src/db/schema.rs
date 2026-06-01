// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (account_id) {
        account_id -> Binary,
        account_data -> Binary,
        last_tx_id -> Binary,
    }
}

diesel::table! {
    chain_state (id) {
        id -> Integer,
        block_num -> BigInt,
        block_header -> Binary,
        chain_mmr -> Binary,
        genesis_commitment -> Binary,
    }
}

diesel::table! {
    note_scripts (script_root) {
        script_root -> Binary,
        script_data -> Binary,
    }
}

diesel::table! {
    notes (nullifier) {
        nullifier -> Binary,
        account_id -> Binary,
        note_data -> Binary,
        note_id -> Nullable<Binary>,
        attempt_count -> Integer,
        last_attempt -> Nullable<BigInt>,
        last_error -> Nullable<Text>,
        committed_at -> Nullable<BigInt>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(accounts, chain_state, note_scripts, notes,);
