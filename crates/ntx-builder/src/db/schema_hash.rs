//! Schema verification to detect database schema changes.
//!
//! Detects:
//!
//! - Direct modifications to the database schema outside of migrations
//! - Running a node against a database created with different set of migrations
//! - Forgetting to reset the database after schema changes i.e. for a specific migration
//!
//! The verification works by creating an in-memory reference database, applying all
//! migrations to it, and comparing its schema against the actual database schema.

use diesel::{Connection, RunQueryDsl, SqliteConnection};
use diesel_migrations::MigrationHarness;
use tracing::instrument;

use crate::COMPONENT;
use crate::db::errors::SchemaVerificationError;
use crate::db::migrations::MIGRATIONS;

/// Represents a schema object for comparison.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SchemaObject {
    object_type: String,
    name: String,
    sql: String,
}

/// Represents a row from the `sqlite_schema` table.
#[derive(diesel::QueryableByName, Debug)]
struct SqliteSchemaRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    schema_type: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    sql: Option<String>,
}

/// Extracts all schema objects from a database connection.
fn extract_schema(
    conn: &mut SqliteConnection,
) -> Result<Vec<SchemaObject>, SchemaVerificationError> {
    let rows: Vec<SqliteSchemaRow> = diesel::sql_query(
        "SELECT type as schema_type, name, sql FROM sqlite_schema \
         WHERE type IN ('table', 'index') \
         AND name NOT LIKE 'sqlite_%' \
         AND name NOT LIKE '__diesel_%' \
         ORDER BY type, name",
    )
    .load(conn)
    .map_err(SchemaVerificationError::SchemaExtraction)?;

    let mut objects: Vec<SchemaObject> = rows
        .into_iter()
        .filter_map(|row| {
            row.sql.map(|sql| SchemaObject {
                object_type: row.schema_type,
                name: row.name,
                sql,
            })
        })
        .collect();

    objects.sort();
    Ok(objects)
}

/// Computes the expected schema by applying migrations to an in-memory database.
fn compute_expected_schema() -> Result<Vec<SchemaObject>, SchemaVerificationError> {
    let mut conn = SqliteConnection::establish(":memory:")
        .map_err(SchemaVerificationError::InMemoryDbCreation)?;

    conn.run_pending_migrations(MIGRATIONS)
        .map_err(SchemaVerificationError::MigrationApplication)?;

    extract_schema(&mut conn)
}

/// Verifies that the database schema matches the expected schema.
///
/// Creates an in-memory database, applies all migrations, and compares schemas.
///
/// # Errors
///
/// Returns `SchemaVerificationError::Mismatch` if schemas differ.
#[instrument(level = "info", target = COMPONENT, skip_all, err)]
pub fn verify_schema(conn: &mut SqliteConnection) -> Result<(), SchemaVerificationError> {
    let expected = compute_expected_schema()?;
    let actual = extract_schema(conn)?;

    if actual != expected {
        let expected_names: Vec<_> = expected.iter().map(|o| &o.name).collect();
        let actual_names: Vec<_> = actual.iter().map(|o| &o.name).collect();

        // Find differences for better error messages.
        let missing: Vec<_> = expected.iter().filter(|e| !actual.contains(e)).collect();
        let extra: Vec<_> = actual.iter().filter(|a| !expected.contains(a)).collect();

        tracing::error!(
            target: COMPONENT,
            ?expected_names,
            ?actual_names,
            missing_count = missing.len(),
            extra_count = extra.len(),
            "Database schema mismatch detected"
        );

        // Log specific differences at debug level.
        for obj in &missing {
            tracing::debug!(target: COMPONENT, name = %obj.name, "Missing or modified: {}", obj.sql);
        }
        for obj in &extra {
            tracing::debug!(target: COMPONENT, name = %obj.name, "Extra or modified: {}", obj.sql);
        }

        return Err(SchemaVerificationError::Mismatch {
            expected_count: expected.len(),
            actual_count: actual.len(),
            missing_count: missing.len(),
            extra_count: extra.len(),
        });
    }

    tracing::info!(
        target: COMPONENT,
        objects = expected.len(),
        "Database schema verification passed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::errors::DatabaseError;
    use crate::db::migrations::apply_migrations;

    #[test]
    fn verify_schema_passes_for_correct_schema() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();
        verify_schema(&mut conn).expect("Should pass for correct schema");
    }

    #[test]
    fn verify_schema_fails_for_added_object() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();

        diesel::sql_query("CREATE TABLE rogue_table (id INTEGER PRIMARY KEY)")
            .execute(&mut conn)
            .unwrap();

        assert!(matches!(
            verify_schema(&mut conn),
            Err(SchemaVerificationError::Mismatch { .. })
        ));
    }

    #[test]
    fn verify_schema_fails_for_removed_object() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();

        diesel::sql_query("DROP TABLE notes").execute(&mut conn).unwrap();

        assert!(matches!(
            verify_schema(&mut conn),
            Err(SchemaVerificationError::Mismatch { .. })
        ));
    }

    #[test]
    fn apply_migrations_succeeds_on_fresh_database() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        apply_migrations(&mut conn).expect("Should succeed on fresh database");
    }

    #[test]
    fn apply_migrations_fails_on_tampered_database() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        conn.run_pending_migrations(MIGRATIONS).unwrap();

        diesel::sql_query("CREATE TABLE tampered (id INTEGER)")
            .execute(&mut conn)
            .unwrap();

        assert!(matches!(apply_migrations(&mut conn), Err(DatabaseError::SchemaVerification(_))));
    }
}
