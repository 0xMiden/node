-- Selects unconsumed FEE_SPONSORSHIP notes bound to the given account's unconsumed feature notes.
-- The binding is by feature note id (the sponsorship's tag is only a discovery hint), so
-- sponsorships whose feature note is unknown, consumed, or targets another account do not match.
SELECT s.feature_note_id, s.note_data FROM sponsorship_notes s
JOIN notes n ON n.note_id = s.feature_note_id
WHERE n.account_id = ?1 AND n.committed_at IS NULL AND s.committed_at IS NULL
