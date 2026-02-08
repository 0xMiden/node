diesel::table! {
    validated_transactions (id, account_id, info) {
        id -> Binary,
        account_id -> Binary,
        info -> Binary,
    }
}
