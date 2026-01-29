diesel::table! {
    transactions (transaction_id) {
        transaction_id -> Binary,
        data -> Binary,
    }
}
