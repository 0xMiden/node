use std::path::PathBuf;

use anyhow::Context;
use diesel::{Connection, SqliteConnection};
use tracing::{info, instrument};

use crate::COMPONENT;
use crate::db::errors::{DatabaseError, DatabaseSetupError};
use crate::db::manager::{ConnectionManager, configure_connection_on_creation};
use crate::db::migrations::apply_migrations;

pub mod errors;
pub(crate) mod manager;

mod migrations;
mod schema_hash;

/// [diesel](https://diesel.rs) generated schema.
pub(crate) mod schema;

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;

pub struct Db {
    pool: deadpool_diesel::Pool<ConnectionManager, deadpool::managed::Object<ConnectionManager>>,
}

impl Db {
    /// Creates a new database file, configures it, and applies migrations.
    ///
    /// This is a synchronous one-shot setup used during node initialization.
    /// For runtime access with a connection pool, use [`Db::load`].
    #[instrument(
        target = COMPONENT,
        name = "ntx_builder.database.bootstrap",
        skip_all,
        fields(path=%database_filepath.display()),
        err,
    )]
    pub fn bootstrap(database_filepath: PathBuf) -> anyhow::Result<()> {
        let mut conn: SqliteConnection = diesel::sqlite::SqliteConnection::establish(
            database_filepath.to_str().context("database filepath is invalid")?,
        )
        .context("failed to open a database connection")?;

        configure_connection_on_creation(&mut conn)?;

        // Run migrations.
        apply_migrations(&mut conn).context("failed to apply database migrations")?;

        Ok(())
    }

    /// Create and commit a transaction with the queries added in the provided closure.
    #[allow(dead_code)]
    pub(crate) async fn transact<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send
            + for<'a, 't> FnOnce(&'a mut SqliteConnection) -> std::result::Result<R, E>
            + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<diesel::result::Error>,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        conn.interact(|conn| <_ as diesel::Connection>::transaction::<R, E, Q>(conn, query))
            .await
            .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Run the query _without_ a transaction.
    pub(crate) async fn query<R, E, Q, M>(&self, msg: M, query: Q) -> std::result::Result<R, E>
    where
        Q: Send + FnOnce(&mut SqliteConnection) -> std::result::Result<R, E> + 'static,
        R: Send + 'static,
        M: Send + ToString,
        E: From<DatabaseError>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| DatabaseError::ConnectionPoolObtainError(Box::new(e)))?;

        conn.interact(move |conn| {
            let r = query(conn)?;
            Ok(r)
        })
        .await
        .map_err(|err| E::from(DatabaseError::interact(&msg.to_string(), &err)))?
    }

    /// Opens a connection pool to an existing database and re-applies pending migrations.
    ///
    /// Use [`Db::bootstrap`] first to create and initialize the database file.
    #[instrument(target = COMPONENT, skip_all)]
    pub async fn load(database_filepath: PathBuf) -> Result<Self, DatabaseSetupError> {
        let manager = ConnectionManager::new(database_filepath.to_str().unwrap());
        let pool = deadpool_diesel::Pool::builder(manager)
            .max_size(16)
            .build()
            .map_err(DatabaseSetupError::PoolBuild)?;

        info!(
            target: COMPONENT,
            sqlite = %database_filepath.display(),
            "Connected to the database"
        );

        let me = Db { pool };
        me.query("migrations", apply_migrations).await?;
        Ok(me)
    }
}
