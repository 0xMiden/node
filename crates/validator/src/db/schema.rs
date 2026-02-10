diesel::table! {
    validated_transactions (id, block_num, account_id, info) {
        id -> Binary,
        block_num -> BigInt,
        account_id -> Binary,
        info -> Binary,
    }
}
