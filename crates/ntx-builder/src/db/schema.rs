// @generated automatically by Diesel CLI.

diesel::table! {
    chain_state (id) {
        id -> Nullable<Integer>,
        block_num -> Integer,
        block_header -> Binary,
    }
}

diesel::table! {
    committed_accounts (account_id) {
        account_id -> Binary,
        account_data -> Binary,
    }
}

diesel::table! {
    committed_notes (nullifier) {
        nullifier -> Binary,
        account_id -> Binary,
        note_data -> Binary,
        attempt_count -> Integer,
        last_attempt -> Nullable<Integer>,
    }
}

diesel::table! {
    inflight_account_deltas (id) {
        id -> Nullable<Integer>,
        account_id -> Binary,
        transaction_id -> Binary,
        account_data -> Binary,
    }
}

diesel::table! {
    inflight_notes (nullifier) {
        nullifier -> Binary,
        account_id -> Binary,
        transaction_id -> Binary,
        note_data -> Binary,
        attempt_count -> Integer,
        last_attempt -> Nullable<Integer>,
    }
}

diesel::table! {
    inflight_nullifiers (nullifier) {
        nullifier -> Binary,
        account_id -> Binary,
        transaction_id -> Binary,
        note_data -> Binary,
        attempt_count -> Integer,
        last_attempt -> Nullable<Integer>,
    }
}

diesel::table! {
    inflight_transactions (transaction_id) {
        transaction_id -> Binary,
        delta_account_id -> Nullable<Binary>,
    }
}

diesel::table! {
    predating_events (account_id, transaction_id) {
        account_id -> Binary,
        transaction_id -> Binary,
        event_data -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    chain_state,
    committed_accounts,
    committed_notes,
    inflight_account_deltas,
    inflight_notes,
    inflight_nullifiers,
    inflight_transactions,
    predating_events,
);
