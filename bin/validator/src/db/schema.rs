// @generated automatically by Diesel CLI.

diesel::table! {
    block_headers (block_num) {
        block_num -> BigInt,
        block_header -> Binary,
    }
}

diesel::table! {
    validated_transactions (id) {
        id -> Binary,
        block_num -> BigInt,
        account_id -> Binary,
        account_patch -> Binary,
        input_notes -> Nullable<Binary>,
        output_notes -> Nullable<Binary>,
        initial_account_hash -> Binary,
        final_account_hash -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(block_headers, validated_transactions,);
