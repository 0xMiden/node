SELECT EXISTS(
    SELECT 1
    FROM notes
    WHERE id = ?1
);
