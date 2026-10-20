SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'notes'), 0);
