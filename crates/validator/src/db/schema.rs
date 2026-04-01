diesel::table! {
    validated_transactions (id) {
        id -> Binary,
        block_num -> BigInt,
        account_id -> Binary,
        account_delta -> Binary,
        input_notes -> Binary,
        output_notes -> Binary,
        initial_account_hash -> Binary,
        final_account_hash -> Binary,
        fee -> Binary,
    }
}

diesel::table! {
    block_headers (block_num) {
        block_num -> BigInt,
        block_header -> Binary,
    }
}
