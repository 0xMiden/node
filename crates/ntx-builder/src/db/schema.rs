// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (order_id) {
        order_id -> Integer,
        account_id -> Binary,
        account_data -> Binary,
        transaction_id -> Nullable<Binary>,
    }
}

diesel::table! {
    chain_state (id) {
        id -> Integer,
        block_num -> BigInt,
        block_header -> Binary,
    }
}

diesel::table! {
    notes (nullifier) {
        nullifier -> Binary,
        account_id -> Binary,
        note_data -> Binary,
        attempt_count -> Integer,
        last_attempt -> Nullable<BigInt>,
        created_by -> Nullable<Binary>,
        consumed_by -> Nullable<Binary>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(accounts, chain_state, notes,);
