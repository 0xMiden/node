use diesel::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use miden_node_db::DatabaseError;
use tracing::instrument;

use crate::COMPONENT;
use crate::db::schema_hash::verify_schema;

// The rebuild is automatically triggered by `build.rs` as described in
// <https://docs.rs/diesel_migrations/latest/diesel_migrations/macro.embed_migrations.html#automatic-rebuilds>.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("src/db/migrations");

#[instrument(level = "debug", target = COMPONENT, skip_all, err)]
pub fn apply_migrations(conn: &mut SqliteConnection) -> Result<(), DatabaseError> {
    let migrations = conn.pending_migrations(MIGRATIONS).expect("In memory migrations never fail");
    tracing::info!(target: COMPONENT, migrations = migrations.len(), "Applying pending migrations");

    let Err(e) = conn.run_pending_migrations(MIGRATIONS) else {
        // Migrations applied successfully, verify schema hash.
        verify_schema(conn)?;
        return Ok(());
    };
    tracing::warn!(target: COMPONENT, "Failed to apply migration: {e:?}");
    // Something went wrong; revert the last migration.
    conn.revert_last_migration(MIGRATIONS)
        .expect("Duality is maintained by the developer");

    Ok(())
}
