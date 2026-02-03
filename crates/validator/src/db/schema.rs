diesel::table! {
    transactions (id, account_id, summary) {
        id -> Binary,
        account_id -> Binary,
        summary -> Binary,
    }
}
