INSERT INTO transaction_logs (
    native_account_id, block_num, transaction_index, log_index,
    transaction_id, emitter, topic, content
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
