mod changelog;
mod comment_reflow;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(about = "Repository maintenance tasks", name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate, render, or release structured changelog entries.
    Changelog(changelog::Changelog),

    /// Reflow safe Rust line-comment blocks.
    FmtComments(FmtComments),
}

#[derive(Debug, Args)]
struct FmtComments {
    /// Rewrite files in place.
    #[arg(long, conflicts_with = "check")]
    write: bool,

    /// Check whether files are already reflowed.
    #[arg(long)]
    check: bool,

    /// Reflow only `///` and `//!` rustdoc comments.
    #[arg(long)]
    doc_comments_only: bool,

    /// Target total line width. Defaults to rustfmt's `comment_width`, or 100.
    #[arg(long)]
    width: Option<usize>,

    /// Path to the rustfmt config used to source `comment_width`.
    #[arg(long, default_value = ".config/rustfmt.toml")]
    rustfmt_config: PathBuf,

    /// Files or directories to process. Defaults to the repository tree.
    paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct RustfmtConfig {
    comment_width: Option<usize>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Changelog(command) => command.run(),
        Command::FmtComments(command) => command.run(),
    }
}

impl FmtComments {
    fn run(&self) -> Result<()> {
        let width = comment_width(self.width, &self.rustfmt_config)?;
        let paths = comment_reflow::rust_files(&self.paths).context("collecting Rust files")?;
        let config = comment_reflow::Config {
            width,
            include_normal_comments: !self.doc_comments_only,
        };

        let mut changed = Vec::new();

        for path in paths {
            let source = fs_err::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let reflowed = comment_reflow::reflow_source(&source, config)
                .with_context(|| format!("reflowing {}", path.display()))?;

            if reflowed != source {
                if self.write {
                    fs_err::write(&path, reflowed)
                        .with_context(|| format!("writing {}", path.display()))?;
                }
                changed.push(path);
            }
        }

        if changed.is_empty() {
            return Ok(());
        }

        if self.write {
            eprintln!("reflowed comments in {} file(s)", changed.len());
            return Ok(());
        }

        for path in &changed {
            eprintln!("comments need reflow: {}", path.display());
        }

        let mode = if self.check { "--check" } else { "default check" };
        bail!(
            "{} file(s) need comment reflow ({mode}); run `cargo xtask fmt-comments --write`",
            changed.len()
        );
    }
}

fn comment_width(explicit: Option<usize>, rustfmt_config: &Path) -> Result<usize> {
    if let Some(width) = explicit {
        return validate_width(width);
    }

    let source = match fs_err::read_to_string(rustfmt_config) {
        Ok(source) => source,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(100),
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", rustfmt_config.display()));
        },
    };

    let config = toml::from_str::<RustfmtConfig>(&source)
        .context("parsing rustfmt config for comment_width")?;
    let width = config.comment_width.unwrap_or(100);

    validate_width(width)
}

fn validate_width(width: usize) -> Result<usize> {
    ensure!(width >= 20, "comment width must be at least 20 columns");
    Ok(width)
}
