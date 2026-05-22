use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use codegen::{Function, Scope};
use fs_err as fs;

use super::Migrator;

pub const GENERATED_MIGRATOR_FILE: &str = "db_migrator.rs";

impl Migrator {
    /// Generates Rust source for a migrator from a migration directory.
    ///
    /// Call this from a `build.rs`, then include the generated file in the crate:
    ///
    /// ```ignore
    /// // build.rs
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     miden_node_db::migration::Migrator::generate("migrations")?;
    ///     Ok(())
    /// }
    ///
    /// // src/lib.rs
    /// include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));
    ///
    /// #[cfg(test)]
    /// mod tests {
    ///     use miden_node_db::migration::SchemaHash;
    ///
    ///     const EXPECTED_SCHEMA_HASHES: [SchemaHash; 3] = [
    ///         SchemaHash::from_hex(
    ///             "1111111111111111111111111111111111111111111111111111111111111111",
    ///         ),
    ///         SchemaHash::from_hex(
    ///             "2222222222222222222222222222222222222222222222222222222222222222",
    ///         ),
    ///         SchemaHash::from_hex(
    ///             "3333333333333333333333333333333333333333333333333333333333333333",
    ///         ),
    ///     ];
    ///
    ///     #[test]
    ///     fn migration_schema_hashes_are_stable() -> anyhow::Result<()> {
    ///         let migrator = super::migrator()?;
    ///
    ///         assert_eq!(migrator.schema_hashes(), &EXPECTED_SCHEMA_HASHES);
    ///         Ok(())
    ///     }
    /// }
    /// ```
    ///
    /// The expected layout is:
    ///
    /// ```text
    /// migrations/
    ///   retired/
    ///     001_legacy.sql
    ///   002_initial.sql
    ///   003_backfill.rs
    ///   003_backfill/
    ///     fixture.bin
    /// ```
    ///
    /// Retired migrations are loaded from lexicographically sorted `.sql` files in `retired`;
    /// the migration name is the file stem. Active migrations are loaded from lexicographically
    /// sorted direct `.sql` and `.rs` files in the migration directory; the migration name is the
    /// file stem. Rust migration files must expose a `pub fn migrate(...)` matching
    /// [`super::CodeMigrationFn`]. Direct subdirectories other than `retired` are ignored by the
    /// framework so callers can keep migration-specific support files next to a migration file.
    ///
    /// The `retired` directory contains SQL retained for fresh database initialization after the
    /// corresponding active migrations no longer need to be supported. Relative migration paths are
    /// resolved from the package manifest directory, i.e. the crate root.
    pub fn generate(migration_dir: impl AsRef<Path>) -> Result<PathBuf> {
        let migration_dir = migration_dir_path(migration_dir.as_ref());
        build_rs::output::rerun_if_changed(&migration_dir);

        let out_path = build_rs::input::out_dir().join(GENERATED_MIGRATOR_FILE);
        let migrations = discover_migrations(&migration_dir)?;
        fs::write(
            &out_path,
            render_migrator(&migrations.retired_migrations, &migrations.active_migrations)?,
        )
        .with_context(|| format!("failed to write generated migrator to {}", out_path.display()))?;
        Ok(out_path)
    }
}

fn migration_dir_path(migration_dir: &Path) -> PathBuf {
    if migration_dir.is_absolute() {
        migration_dir.to_path_buf()
    } else {
        build_rs::input::cargo_manifest_dir().join(migration_dir)
    }
}

#[derive(Debug)]
struct DiscoveredMigrations {
    retired_migrations: Vec<SqlMigration>,
    active_migrations: Vec<ActiveMigration>,
}

#[derive(Debug)]
struct SqlMigration {
    name: String,
    path: PathBuf,
}

#[derive(Debug)]
struct CodeMigration {
    name: String,
    module_ident: String,
    path: PathBuf,
}

#[derive(Debug)]
enum ActiveMigration {
    Sql(SqlMigration),
    Code(CodeMigration),
}

fn discover_migrations(migration_dir: &Path) -> Result<DiscoveredMigrations> {
    ensure!(
        migration_dir.is_dir(),
        "migration path is not a directory: {}",
        migration_dir.display()
    );

    let retired_migrations = discover_retired_migrations(migration_dir)?;
    let active_migrations = discover_active_migrations(migration_dir)?;
    ensure!(
        !retired_migrations.is_empty() || !active_migrations.is_empty(),
        "migration directory contains no migrations: {}",
        migration_dir.display()
    );

    Ok(DiscoveredMigrations { retired_migrations, active_migrations })
}

fn discover_retired_migrations(migration_dir: &Path) -> Result<Vec<SqlMigration>> {
    let retired_dir = migration_dir.join("retired");
    if !retired_dir.exists() {
        return Ok(Vec::new());
    }

    ensure!(
        retired_dir.is_dir(),
        "retired migration path is not a directory: {}",
        retired_dir.display()
    );

    let mut seen_prefixes = HashSet::new();
    let mut migrations = Vec::new();
    for entry in read_dir_sorted(&retired_dir)? {
        let path = entry.path();
        ensure!(path.is_file(), "retired migration entry is not a file: {}", path.display());
        ensure!(
            path.extension() == Some(OsStr::new("sql")),
            "retired migration file must use .sql extension: {}",
            path.display()
        );

        let name = file_stem(&path)?;
        let prefix = migration_prefix(&name, &path)?;
        ensure!(
            seen_prefixes.insert(prefix.to_owned()),
            "duplicate retired migration prefix {prefix:?}"
        );

        migrations.push(SqlMigration { name, path: absolute_path(&path)? });
    }

    Ok(migrations)
}

fn discover_active_migrations(migration_dir: &Path) -> Result<Vec<ActiveMigration>> {
    let mut seen_prefixes = HashSet::new();
    let mut migrations = Vec::new();
    for entry in read_dir_sorted(migration_dir)? {
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        ensure!(path.is_file(), "active migration entry is not a file: {}", path.display());

        let name = file_stem(&path)?;
        let prefix = migration_prefix(&name, &path)?;
        ensure!(
            seen_prefixes.insert(prefix.to_owned()),
            "duplicate active migration prefix {prefix:?}"
        );

        match path.extension().and_then(OsStr::to_str) {
            Some("sql") => {
                migrations
                    .push(ActiveMigration::Sql(SqlMigration { name, path: absolute_path(&path)? }));
            },
            Some("rs") => {
                let module_ident = module_ident(&name)?;

                migrations.push(ActiveMigration::Code(CodeMigration {
                    name,
                    module_ident,
                    path: absolute_path(&path)?,
                }));
            },
            _ => {
                bail!("active migration file must use .sql or .rs extension: {}", path.display());
            },
        }
    }

    Ok(migrations)
}

/// Renders the Rust source written by [`Migrator::generate`].
///
/// For one retired migration named `001_legacy`, one SQL migration named `002_initial`, and one
/// Rust migration named `003_backfill`,
/// the generated file has this shape:
///
/// ```ignore
/// #[path = "/path/to/migrations/003_backfill.rs"]
/// mod migration_003_backfill;
///
/// pub fn migrator() -> ::anyhow::Result<::miden_node_db::migration::Migrator> {
///     ::miden_node_db::migration::Migrator::builder()?
///         .push_retired("001_legacy", include_str!("/path/to/migrations/retired/001_legacy.sql"))?
///         .push_sql("002_initial", include_str!("/path/to/migrations/002_initial.sql"))?
///         .push_code("003_backfill", migration_003_backfill::migrate)?
///         .build()
/// }
/// ```
fn render_migrator(
    retired_migrations: &[SqlMigration],
    active_migrations: &[ActiveMigration],
) -> Result<String> {
    let mut scope = Scope::new();

    for migration in active_migrations {
        let ActiveMigration::Code(migration) = migration else {
            continue;
        };

        let path = format!("{:?}", rust_path(&migration.path)?);
        scope.raw(format!("#[path = {path}]\nmod {};", migration.module_ident));
    }

    let mut function = Function::new("migrator");
    function.vis("pub");
    function.ret("::anyhow::Result<::miden_node_db::migration::Migrator>");
    function.line("::miden_node_db::migration::Migrator::builder()?");

    for migration in retired_migrations {
        let name = format!("{:?}", migration.name);
        let path = format!("{:?}", rust_path(&migration.path)?);
        function.line(format!("    .push_retired({name}, include_str!({path}))?"));
    }

    for migration in active_migrations {
        match migration {
            ActiveMigration::Sql(migration) => {
                let name = format!("{:?}", migration.name);
                let path = format!("{:?}", rust_path(&migration.path)?);
                function.line(format!("    .push_sql({name}, include_str!({path}))?"));
            },
            ActiveMigration::Code(migration) => {
                let name = format!("{:?}", migration.name);
                function
                    .line(format!("    .push_code({name}, {}::migrate)?", migration.module_ident));
            },
        }
    }

    function.line("    .build()");
    scope.push_fn(function);

    let mut source = scope.to_string();
    source.push('\n');
    Ok(source)
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to read migration directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!("failed to read migration directory entry in {}", dir.display())
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize migration path {}", path.display()))
}

fn file_stem(path: &Path) -> Result<String> {
    path.file_stem().and_then(OsStr::to_str).map(str::to_owned).with_context(|| {
        format!("migration file has invalid UTF-8 stem or no stem: {}", path.display())
    })
}

fn migration_prefix<'a>(name: &'a str, path: &Path) -> Result<&'a str> {
    let bytes = name.as_bytes();
    ensure!(
        bytes.len() > 4
            && bytes[0].is_ascii_digit()
            && bytes[1].is_ascii_digit()
            && bytes[2].is_ascii_digit()
            && bytes[3] == b'_'
            && name[4..].chars().any(|ch| ch.is_ascii_alphanumeric()),
        "migration file name must start with a three-digit prefix followed by an underscore, e.g. \
         001_initial: {}",
        path.display()
    );

    ensure!(
        &name[..3] != "000",
        "migration file prefix must start at 001: {}",
        path.display()
    );

    Ok(&name[..3])
}

/// Converts a migration folder name into a Rust module identifier.
///
/// The generated identifier is prefixed with `migration_`, ASCII alphanumeric characters are
/// lowercased, and every other character is replaced with `_`. For example,
/// `001--Backfill-Accounts` becomes `migration_001__backfill_accounts`.
fn module_ident(name: &str) -> Result<String> {
    ensure!(
        name.chars().any(|ch| ch.is_ascii_alphanumeric()),
        "migration name {name:?} cannot be converted to a Rust module identifier"
    );

    let ident = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    Ok(format!("migration_{ident}"))
}

fn rust_path(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("migration path is not valid UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    #[test]
    fn renders_migrations_in_lexicographic_order() -> Result<()> {
        let root = unique_temp_dir("renders_migrations_in_lexicographic_order")?;
        fs::create_dir_all(root.join("retired"))?;
        fs::create_dir_all(root.join("003_backfill"))?;
        fs::write(root.join("retired").join("001_legacy.sql"), "CREATE TABLE t (id INTEGER);")?;
        fs::write(root.join("002_indexes.sql"), "CREATE INDEX idx ON t(id);")?;
        fs::write(
            root.join("003_backfill.rs"),
            "pub fn migrate(_: &rusqlite::Transaction<'_>) -> anyhow::Result<()> { Ok(()) }",
        )?;
        fs::write(root.join("003_backfill").join("fixture.bin"), "supporting data")?;

        let retired = discover_retired_migrations(&root)?;
        let active = discover_active_migrations(&root)?;
        let rendered = render_migrator(&retired, &active)?;

        let legacy = rendered.find("\"001_legacy\"").expect("legacy migration is rendered");
        let indexes = rendered.find("\"002_indexes\"").expect("index migration is rendered");
        let backfill = rendered.find("\"003_backfill\"").expect("code migration is rendered");

        assert!(legacy < indexes);
        assert!(indexes < backfill);
        assert!(rendered.contains("include_str!("));
        assert!(rendered.contains(".push_retired("));
        assert!(rendered.contains(".push_sql("));
        assert!(rendered.contains(".push_code("));
        assert!(!rendered.contains(".push_base("));
        assert!(rendered.contains("migration_003_backfill::migrate"));
        assert!(rendered.contains(".build()\n}\n"));
        assert!(!rendered.contains("Ok(migrator)"));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_empty_migration_directory() -> Result<()> {
        let root = unique_temp_dir("rejects_empty_migration_directory")?;

        let err = discover_migrations(&root).expect_err("empty migration directory should fail");

        assert!(err.to_string().contains("contains no migrations"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_retired_migration_entries() -> Result<()> {
        let root = unique_temp_dir("rejects_invalid_retired_migration_entries")?;
        fs::create_dir_all(root.join("retired"))?;
        fs::write(root.join("retired").join("001_init.txt"), "CREATE TABLE t (id INTEGER);")?;

        let err =
            discover_retired_migrations(&root).expect_err("invalid retired entry should fail");

        assert!(err.to_string().contains("must use .sql extension"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_active_migration_file_extension() -> Result<()> {
        let root = unique_temp_dir("rejects_invalid_active_migration_file_extension")?;
        fs::write(root.join("001_init.txt"), "CREATE TABLE t (id INTEGER);")?;

        let err = discover_active_migrations(&root).expect_err("invalid entry should fail");

        assert!(err.to_string().contains("must use .sql or .rs extension"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_active_migrations_without_three_digit_prefix() -> Result<()> {
        let root = unique_temp_dir("rejects_active_migrations_without_three_digit_prefix")?;
        fs::write(root.join("1_init.sql"), "CREATE TABLE t (id INTEGER);")?;

        let err = discover_active_migrations(&root).expect_err("invalid prefix should fail");

        assert!(err.to_string().contains("three-digit prefix"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_retired_migrations_without_three_digit_prefix() -> Result<()> {
        let root = unique_temp_dir("rejects_retired_migrations_without_three_digit_prefix")?;
        fs::create_dir_all(root.join("retired"))?;
        fs::write(root.join("retired").join("init.sql"), "CREATE TABLE t (id INTEGER);")?;

        let err = discover_retired_migrations(&root).expect_err("invalid prefix should fail");

        assert!(err.to_string().contains("three-digit prefix"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_duplicate_active_migration_prefixes() -> Result<()> {
        let root = unique_temp_dir("rejects_duplicate_active_migration_prefixes")?;
        fs::write(root.join("001_init.sql"), "CREATE TABLE t (id INTEGER);")?;
        fs::write(root.join("001_indexes.sql"), "CREATE INDEX idx ON t(id);")?;

        let err = discover_active_migrations(&root).expect_err("duplicate prefix should fail");

        assert!(err.to_string().contains("duplicate active migration prefix"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_duplicate_retired_migration_prefixes() -> Result<()> {
        let root = unique_temp_dir("rejects_duplicate_retired_migration_prefixes")?;
        fs::create_dir_all(root.join("retired"))?;
        fs::write(root.join("retired").join("001_init.sql"), "CREATE TABLE t (id INTEGER);")?;
        fs::write(root.join("retired").join("001_indexes.sql"), "CREATE INDEX idx ON t(id);")?;

        let err = discover_retired_migrations(&root).expect_err("duplicate prefix should fail");

        assert!(err.to_string().contains("duplicate retired migration prefix"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_zero_migration_prefix() -> Result<()> {
        let root = unique_temp_dir("rejects_zero_migration_prefix")?;
        fs::write(root.join("000_init.sql"), "CREATE TABLE t (id INTEGER);")?;

        let err = discover_active_migrations(&root).expect_err("zero prefix should fail");

        assert!(err.to_string().contains("prefix must start at 001"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn module_ident_preserves_repeated_separators() -> Result<()> {
        assert_eq!(module_ident("001--backfill")?, "migration_001__backfill");
        Ok(())
    }

    #[test]
    fn migration_dir_path_resolves_relative_paths_from_manifest_dir() {
        assert_eq!(
            migration_dir_path(Path::new("migrations")),
            build_rs::input::cargo_manifest_dir().join("migrations")
        );

        let absolute = env::temp_dir().join("miden-node-db-absolute-migrations");
        assert_eq!(migration_dir_path(&absolute), absolute);
    }

    fn unique_temp_dir(name: &str) -> Result<PathBuf> {
        let dir = env::temp_dir().join(format!("miden-node-db-{name}-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}
