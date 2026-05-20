use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use codegen::{Function, Scope};
use fs_err as fs;

use super::Migrator;

pub const GENERATED_MIGRATOR_FILE: &str = "db_migrator.rs";
pub const CODE_MIGRATION_FILE: &str = "migration.rs";

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
    ///     001_initial.sql
    ///     002_indexes.sql
    ///   code/
    ///     003_backfill/
    ///       migration.rs
    /// ```
    ///
    /// Retired migrations are loaded from lexicographically sorted `.sql` files in `retired`;
    /// the migration name is the file stem. Code migrations are loaded from lexicographically
    /// sorted folders in `code`; the migration name is the folder name. Each code folder must
    /// contain `migration.rs` and that file must expose a `pub fn migrate(...)` matching
    /// [`super::CodeMigrationFn`].
    ///
    /// The `retired` directory contains SQL retained for fresh database initialization after the
    /// corresponding code migrations no longer need to be supported. Relative migration paths are
    /// resolved from the package manifest directory, i.e. the crate root.
    pub fn generate(migration_dir: impl AsRef<Path>) -> Result<PathBuf> {
        let migration_dir = migration_dir_path(migration_dir.as_ref());
        build_rs::output::rerun_if_changed(&migration_dir);

        let out_path = build_rs::input::out_dir().join(GENERATED_MIGRATOR_FILE);
        let migrations = discover_migrations(&migration_dir)?;
        fs::write(
            &out_path,
            render_migrator(&migrations.retired_migrations, &migrations.code_migrations)?,
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
    code_migrations: Vec<CodeMigration>,
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

fn discover_migrations(migration_dir: &Path) -> Result<DiscoveredMigrations> {
    ensure!(
        migration_dir.is_dir(),
        "migration path is not a directory: {}",
        migration_dir.display()
    );

    let retired_migrations = discover_retired_migrations(migration_dir)?;
    let code_migrations = discover_code_migrations(migration_dir)?;
    ensure!(
        !retired_migrations.is_empty() || !code_migrations.is_empty(),
        "migration directory contains no migrations: {}",
        migration_dir.display()
    );

    Ok(DiscoveredMigrations { retired_migrations, code_migrations })
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

    let mut migrations = Vec::new();
    for entry in read_dir_sorted(&retired_dir)? {
        let path = entry.path();
        ensure!(path.is_file(), "retired migration entry is not a file: {}", path.display());
        ensure!(
            path.extension() == Some(OsStr::new("sql")),
            "retired migration file must use .sql extension: {}",
            path.display()
        );

        migrations.push(SqlMigration {
            name: file_stem(&path)?,
            path: absolute_path(&path)?,
        });
    }

    Ok(migrations)
}

fn discover_code_migrations(migration_dir: &Path) -> Result<Vec<CodeMigration>> {
    let code_dir = migration_dir.join("code");
    if !code_dir.exists() {
        return Ok(Vec::new());
    }

    ensure!(
        code_dir.is_dir(),
        "code migration path is not a directory: {}",
        code_dir.display()
    );

    // Folder names are converted into Rust module identifiers lossy, e.g. `001-backfill` and
    // `001_backfill` both become `migration_001_backfill`. To prevent this, we track seen
    // identifiers and reject any collisions.
    let mut seen_idents = HashSet::new();
    let mut migrations = Vec::new();
    for entry in read_dir_sorted(&code_dir)? {
        let path = entry.path();
        ensure!(path.is_dir(), "code migration entry is not a directory: {}", path.display());

        let name = file_name(&path)?;
        let module_ident = module_ident(&name)?;
        ensure!(
            seen_idents.insert(module_ident.clone()),
            "code migration module identifier collision for migration {name:?}"
        );

        let migration_rs = path.join(CODE_MIGRATION_FILE);
        ensure!(
            migration_rs.is_file(),
            "code migration {} is missing {}",
            path.display(),
            CODE_MIGRATION_FILE
        );

        migrations.push(CodeMigration {
            name,
            module_ident,
            path: absolute_path(&migration_rs)?,
        });
    }

    Ok(migrations)
}

/// Renders the Rust source written by [`Migrator::generate`].
///
/// For one retired migration named `001_initial` and one code migration named `002_backfill`,
/// the generated file has this shape:
///
/// ```ignore
/// #[path = "/path/to/migrations/code/002_backfill/migration.rs"]
/// mod migration_002_backfill;
///
/// pub fn migrator() -> ::anyhow::Result<::miden_node_db::migration::Migrator> {
///     ::miden_node_db::migration::Migrator::builder()?
///         .push_retired("001_initial", include_str!("/path/to/migrations/retired/001_initial.sql"))?
///         .push_code("002_backfill", migration_002_backfill::migrate)?
///         .build()
/// }
/// ```
fn render_migrator(
    retired_migrations: &[SqlMigration],
    code_migrations: &[CodeMigration],
) -> Result<String> {
    let mut scope = Scope::new();

    for migration in code_migrations {
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

    for migration in code_migrations {
        let name = format!("{:?}", migration.name);
        function.line(format!("    .push_code({name}, {}::migrate)?", migration.module_ident));
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

fn file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(str::to_owned)
        .with_context(|| format!("migration path has invalid UTF-8 name: {}", path.display()))
}

fn file_stem(path: &Path) -> Result<String> {
    path.file_stem().and_then(OsStr::to_str).map(str::to_owned).with_context(|| {
        format!("migration file has invalid UTF-8 stem or no stem: {}", path.display())
    })
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
        fs::create_dir_all(root.join("code").join("003_backfill"))?;
        fs::write(root.join("retired").join("002_indexes.sql"), "CREATE INDEX idx ON t(id);")?;
        fs::write(root.join("retired").join("001_init.sql"), "CREATE TABLE t (id INTEGER);")?;
        fs::write(
            root.join("code").join("003_backfill").join(CODE_MIGRATION_FILE),
            "pub fn migrate(_: &rusqlite::Transaction<'_>) -> anyhow::Result<()> { Ok(()) }",
        )?;

        let retired = discover_retired_migrations(&root)?;
        let code = discover_code_migrations(&root)?;
        let rendered = render_migrator(&retired, &code)?;

        let init = rendered.find("\"001_init\"").expect("init migration is rendered");
        let indexes = rendered.find("\"002_indexes\"").expect("index migration is rendered");
        let backfill = rendered.find("\"003_backfill\"").expect("code migration is rendered");

        assert!(init < indexes);
        assert!(indexes < backfill);
        assert!(rendered.contains("include_str!("));
        assert!(rendered.contains(".push_retired("));
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
    fn rejects_code_migration_missing_rust_file() -> Result<()> {
        let root = unique_temp_dir("rejects_code_migration_missing_rust_file")?;
        fs::create_dir_all(root.join("code").join("001_backfill"))?;

        let err = discover_code_migrations(&root).expect_err("missing migration.rs should fail");

        assert!(err.to_string().contains("is missing migration.rs"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn rejects_code_migration_module_identifier_collisions() -> Result<()> {
        let root = unique_temp_dir("rejects_code_migration_module_identifier_collisions")?;
        fs::create_dir_all(root.join("code").join("001-backfill"))?;
        fs::create_dir_all(root.join("code").join("001_backfill"))?;
        fs::write(
            root.join("code").join("001-backfill").join(CODE_MIGRATION_FILE),
            "pub fn migrate(_: &rusqlite::Transaction<'_>) -> anyhow::Result<()> { Ok(()) }",
        )?;
        fs::write(
            root.join("code").join("001_backfill").join(CODE_MIGRATION_FILE),
            "pub fn migrate(_: &rusqlite::Transaction<'_>) -> anyhow::Result<()> { Ok(()) }",
        )?;

        let err = discover_code_migrations(&root).expect_err("module collision should fail");

        assert!(err.to_string().contains("module identifier collision"));
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
