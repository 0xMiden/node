use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use fs_err as fs;

pub const GENERATED_MIGRATOR_FILE: &str = "db_migrator.rs";
pub const CODE_MIGRATION_FILE: &str = "migration.rs";

/// Generates Rust source for a migrator from a migration directory.
///
/// Call this from a `build.rs`, then include the generated file in the crate:
///
/// ```ignore
/// // build.rs
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     miden_node_db::migration::build_script::generate_migrator("migrations")?;
///     Ok(())
/// }
///
/// // src/lib.rs
/// include!(concat!(env!("OUT_DIR"), "/db_migrator.rs"));
/// ```
///
/// The expected layout is:
///
/// ```text
/// migrations/
///   base/
///     001_initial.sql
///     002_indexes.sql
///   code/
///     003_backfill/
///       migration.rs
/// ```
///
/// Base migrations are loaded from lexicographically sorted `.sql` files in `base`; the migration
/// name is the file stem. Code migrations are loaded from lexicographically sorted folders in
/// `code`; the migration name is the folder name. Each code folder must contain
/// [`CODE_MIGRATION_FILE`] and that file must expose a `pub fn migrate(...)` matching
/// [`super::CodeMigrationFn`].
pub fn generate_migrator(migration_dir: impl AsRef<Path>) -> Result<PathBuf> {
    generate_migrator_to(migration_dir, GENERATED_MIGRATOR_FILE)
}

/// Generates Rust source for a migrator into a specific file name under `OUT_DIR`.
pub fn generate_migrator_to(
    migration_dir: impl AsRef<Path>,
    output_file: impl AsRef<Path>,
) -> Result<PathBuf> {
    let migration_dir = migration_dir.as_ref();
    let output_file = output_file.as_ref();

    ensure!(
        migration_dir.is_dir(),
        "migration path is not a directory: {}",
        migration_dir.display()
    );
    ensure!(
        output_file.file_name() == Some(output_file.as_os_str()),
        "generated migrator output must be a file name, got {}",
        output_file.display()
    );

    let out_path = build_rs::input::out_dir().join(output_file);

    emit_rerun_if_changed(migration_dir);
    let base_migrations = discover_base_migrations(migration_dir)?;
    let code_migrations = discover_code_migrations(migration_dir)?;
    ensure!(
        !base_migrations.is_empty() || !code_migrations.is_empty(),
        "migration directory contains no migrations: {}",
        migration_dir.display()
    );

    fs::write(&out_path, render_migrator(&base_migrations, &code_migrations)?)
        .with_context(|| format!("failed to write generated migrator to {}", out_path.display()))?;

    Ok(out_path)
}

#[derive(Debug)]
struct BaseMigration {
    name: String,
    path: PathBuf,
}

#[derive(Debug)]
struct CodeMigration {
    name: String,
    module_ident: String,
    path: PathBuf,
}

fn discover_base_migrations(migration_dir: &Path) -> Result<Vec<BaseMigration>> {
    let base_dir = migration_dir.join("base");
    emit_rerun_if_changed(&base_dir);
    if !base_dir.exists() {
        return Ok(Vec::new());
    }

    ensure!(
        base_dir.is_dir(),
        "base migration path is not a directory: {}",
        base_dir.display()
    );

    let mut migrations = Vec::new();
    for entry in read_dir_sorted(&base_dir)? {
        let path = entry.path();
        ensure!(path.is_file(), "base migration entry is not a file: {}", path.display());
        ensure!(
            path.extension() == Some(OsStr::new("sql")),
            "base migration file must use .sql extension: {}",
            path.display()
        );

        emit_rerun_if_changed(&path);
        migrations.push(BaseMigration {
            name: file_stem(&path)?,
            path: absolute_path(&path)?,
        });
    }

    Ok(migrations)
}

fn discover_code_migrations(migration_dir: &Path) -> Result<Vec<CodeMigration>> {
    let code_dir = migration_dir.join("code");
    emit_rerun_if_changed(&code_dir);
    if !code_dir.exists() {
        return Ok(Vec::new());
    }

    ensure!(
        code_dir.is_dir(),
        "code migration path is not a directory: {}",
        code_dir.display()
    );

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

        emit_rerun_if_changed(&path);
        emit_rerun_if_changed(&migration_rs);
        migrations.push(CodeMigration {
            name,
            module_ident,
            path: absolute_path(&migration_rs)?,
        });
    }

    Ok(migrations)
}

fn render_migrator(
    base_migrations: &[BaseMigration],
    code_migrations: &[CodeMigration],
) -> Result<String> {
    let mut source = String::new();

    for migration in code_migrations {
        source.push_str("#[path = ");
        push_rust_string(&mut source, rust_path(&migration.path)?);
        source.push_str("]\n");
        source.push_str("mod ");
        source.push_str(&migration.module_ident);
        source.push_str(";\n");
    }

    if !code_migrations.is_empty() {
        source.push('\n');
    }

    source.push_str(
        "pub fn migrator() -> ::anyhow::Result<::miden_node_db::migration::Migrator> {\n    \
         let migrator = ::miden_node_db::migration::Migrator::builder()?",
    );

    for migration in base_migrations {
        source.push_str("\n        .push_base(");
        push_rust_string(&mut source, &migration.name);
        source.push_str(", include_str!(");
        push_rust_string(&mut source, rust_path(&migration.path)?);
        source.push_str("))?");
    }

    for migration in code_migrations {
        source.push_str("\n        .push_code(");
        push_rust_string(&mut source, &migration.name);
        source.push_str(", ");
        source.push_str(&migration.module_ident);
        source.push_str("::migrate)?");
    }

    source.push_str("\n        .build();\n    Ok(migrator)\n}\n");
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

fn module_ident(name: &str) -> Result<String> {
    let mut ident = String::from("migration_");
    let mut has_name_part = false;
    let mut last_was_underscore = true;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            ident.push(ch.to_ascii_lowercase());
            has_name_part = true;
            last_was_underscore = false;
        } else if !last_was_underscore {
            ident.push('_');
            last_was_underscore = true;
        }
    }

    if last_was_underscore {
        ident.pop();
    }

    if !has_name_part {
        bail!("migration name {name:?} cannot be converted to a Rust module identifier");
    }

    Ok(ident)
}

fn rust_path(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("migration path is not valid UTF-8: {}", path.display()))
}

fn push_rust_string(source: &mut String, value: &str) {
    source.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => source.push_str("\\\\"),
            '"' => source.push_str("\\\""),
            '\n' => source.push_str("\\n"),
            '\r' => source.push_str("\\r"),
            '\t' => source.push_str("\\t"),
            ch => source.push(ch),
        }
    }
    source.push('"');
}

fn emit_rerun_if_changed(path: &Path) {
    build_rs::output::rerun_if_changed(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn renders_migrations_in_lexicographic_order() -> Result<()> {
        let root = unique_temp_dir("renders_migrations_in_lexicographic_order")?;
        fs::create_dir_all(root.join("base"))?;
        fs::create_dir_all(root.join("code").join("003_backfill"))?;
        fs::write(root.join("base").join("002_indexes.sql"), "CREATE INDEX idx ON t(id);")?;
        fs::write(root.join("base").join("001_init.sql"), "CREATE TABLE t (id INTEGER);")?;
        fs::write(
            root.join("code").join("003_backfill").join(CODE_MIGRATION_FILE),
            "pub fn migrate(_: &rusqlite::Transaction<'_>) -> anyhow::Result<()> { Ok(()) }",
        )?;

        let base = discover_base_migrations(&root)?;
        let code = discover_code_migrations(&root)?;
        let rendered = render_migrator(&base, &code)?;

        let init = rendered.find("\"001_init\"").expect("init migration is rendered");
        let indexes = rendered.find("\"002_indexes\"").expect("index migration is rendered");
        let backfill = rendered.find("\"003_backfill\"").expect("code migration is rendered");

        assert!(init < indexes);
        assert!(indexes < backfill);
        assert!(rendered.contains("include_str!("));
        assert!(rendered.contains("migration_003_backfill::migrate"));

        fs::remove_dir_all(root)?;
        Ok(())
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
