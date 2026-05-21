//! Provides a framework for SQLite migrations.
//!
//! Migrations are built as an ordered [`Migrator`] with two phases. Retired migrations are retained
//! as pure SQL and are only used to initialize fresh databases. Code migrations are Rust functions
//! that run after the retired SQL set and remain supported for existing databases. This lets old
//! code migrations eventually be converted into retired SQL once their upgrade path no longer needs
//! to be supported.
//!
//! The database version is stored in SQLite's `PRAGMA user_version`. Each migration also has an
//! expected [`SchemaHash`] computed by applying migrations to an in-memory reference database
//! during builder construction. Runtime migration commits only after the resulting schema hash
//! matches the expected hash.
//!
//! Build migrators manually with [`Migrator::builder`], or generate one from a migration directory
//! with [`Migrator::generate`] in a `build.rs`. Callers should snapshot [`Migrator::schema_hashes`]
//! in tests to catch accidental schema drift and to prove that retired SQL still produces the same
//! schema as the code migration it replaced.

mod build_script;
mod builder;
mod entry;
mod migrator;
mod schema;

pub use builder::MigratorBuilder;
pub use entry::CodeMigrationFn;
pub use migrator::Migrator;
pub use schema::SchemaHash;
