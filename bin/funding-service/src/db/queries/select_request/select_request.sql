SELECT sequence, target_account_id, amount, serial_number, accepted_at,
       transaction_id, committed_in_block, confirmed_at
FROM requests
WHERE note_id = ?1;
