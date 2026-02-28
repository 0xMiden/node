diesel::table! {
    validated_transactions (id, block_num, account_id, transaction) {
        id -> Binary,
        block_num -> BigInt,
        account_id -> Binary,
        transaction -> Binary,
    }
}
