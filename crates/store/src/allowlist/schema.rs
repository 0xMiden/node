diesel::table! {
    account_allowlist (id) {
        id -> Integer,
        account_id -> Nullable<Binary>,
        invitation_digest -> Nullable<Binary>,
        created_at -> BigInt,
    }
}
