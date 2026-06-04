mod entry;
mod render;

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Args as ClapArgs, Subcommand};

use self::entry::{
    collect_entry_files,
    load_file,
    load_version,
    validate_date,
    validate_file_layout,
    validate_version,
};
use self::render::{prepend_to_changelog, render_section};

const CHANGELOG_DIR: &str = "changelog.d";
const CHANGELOG_FILE: &str = "CHANGELOG.md";

#[derive(Debug, ClapArgs)]
pub struct Changelog {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate structured changelog files.
    Check(Check),

    /// Render a version's changelog section to stdout.
    Render(Render),

    /// Prepend a finalized version section to CHANGELOG.md.
    Release(Release),
}

#[derive(Debug, ClapArgs)]
struct Check {
    /// Changelog entry root directory.
    #[arg(long, default_value = CHANGELOG_DIR)]
    dir: PathBuf,

    /// Validate only one version directory.
    #[arg(long)]
    version: Option<String>,

    /// Specific changelog files to validate. Defaults to all files under --dir.
    files: Vec<PathBuf>,
}

#[derive(Debug, ClapArgs)]
struct Render {
    /// Changelog entry root directory.
    #[arg(long, default_value = CHANGELOG_DIR)]
    dir: PathBuf,

    /// Version directory to render, for example v0.15.0.
    #[arg(long)]
    version: String,

    /// Date to render in the section header. Defaults to "Unreleased".
    #[arg(long)]
    date: Option<String>,
}

#[derive(Debug, ClapArgs)]
struct Release {
    /// Changelog entry root directory.
    #[arg(long, default_value = CHANGELOG_DIR)]
    dir: PathBuf,

    /// Changelog file to update.
    #[arg(long, default_value = CHANGELOG_FILE)]
    changelog: PathBuf,

    /// Version directory to release, for example v0.15.0.
    #[arg(long)]
    version: String,

    /// Release date in YYYY-MM-DD format.
    #[arg(long)]
    date: String,

    /// Leave changelog.d/<version>/ in place after updating CHANGELOG.md.
    #[arg(long)]
    keep_entries: bool,
}

impl Changelog {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            Command::Check(command) => command.run(),
            Command::Render(command) => command.run(),
            Command::Release(command) => command.run(),
        }
    }
}

impl Check {
    fn run(&self) -> Result<()> {
        if let Some(version) = &self.version {
            validate_version(version)?;
        }

        let files = if self.files.is_empty() {
            collect_entry_files(&self.dir, self.version.as_deref())?
        } else {
            self.files.clone()
        };

        for file in &files {
            validate_file_layout(file, &self.dir)?;
            let _entries = load_file(file)?;
        }

        eprintln!("validated {} changelog file(s)", files.len());
        Ok(())
    }
}

impl Render {
    fn run(&self) -> Result<()> {
        validate_version(&self.version)?;
        if let Some(date) = &self.date {
            validate_date(date)?;
        }

        let entries = load_version(&self.dir, &self.version)?;
        ensure!(
            !entries.is_empty(),
            "no changelog entries found in {}/{}",
            self.dir.display(),
            self.version
        );

        let date = self.date.as_deref().unwrap_or("Unreleased");
        print!("{}", render_section(&self.version, date, &entries));

        Ok(())
    }
}

impl Release {
    fn run(&self) -> Result<()> {
        validate_version(&self.version)?;
        validate_date(&self.date)?;

        let entries = load_version(&self.dir, &self.version)?;
        ensure!(
            !entries.is_empty(),
            "no changelog entries found in {}/{}",
            self.dir.display(),
            self.version
        );

        let section = render_section(&self.version, &self.date, &entries);
        prepend_to_changelog(&self.changelog, &self.version, &section)?;

        if !self.keep_entries {
            let version_dir = self.dir.join(&self.version);
            fs_err::remove_dir_all(&version_dir)
                .with_context(|| format!("removing {}", version_dir.display()))?;
        }

        eprintln!("released {} changelog entries for {}", entries.len(), self.version);

        Ok(())
    }
}
