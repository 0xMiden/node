SELECT transaction_id, emitter, topic, content
FROM transaction_logs
WHERE native_account_id = ?1 AND block_num = ?2 AND transaction_index = ?3
ORDER BY log_index
LIMIT ?4
