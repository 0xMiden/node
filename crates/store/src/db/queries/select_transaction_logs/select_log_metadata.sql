SELECT log_index,
       typeof(transaction_id) = 'blob' AND length(transaction_id) = 32
       AND typeof(emitter) = 'blob' AND length(emitter) = 15
       AND typeof(topic) = 'blob' AND length(topic) = 16
       AND typeof(content) = 'blob',
       length(content)
FROM transaction_logs
WHERE native_account_id = ?1 AND block_num = ?2 AND transaction_index = ?3
ORDER BY log_index
LIMIT ?4
