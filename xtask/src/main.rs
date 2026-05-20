mod comment_reflow;

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Repository maintenance tasks", name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reflow safe Rust line-comment blocks.
    FmtComments(FmtCommentsArgs),
}

#[derive(Debug, Args)]
struct FmtCommentsArgs {
    /// Rewrite files in place.
    #[arg(long, conflicts_with = "check")]
    write: bool,

    /// Check whether files are already reflowed.
    #[arg(long)]
    check: bool,

    /// Reflow only `///` and `//!` rustdoc comments.
    #[arg(long)]
    doc_comments_only: bool,

    /// Target total line width. Defaults to rustfmt.toml's `comment_width`, or 100.
    #[arg(long)]
    width: Option<usize>,

    /// Files or directories to process. Defaults to the repository tree.
    paths: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::FmtComments(args) => run_fmt_comments(&args),
    }
}

fn run_fmt_comments(args: &FmtCommentsArgs) -> Result<()> {
    let width = comment_width(args.width)?;
    let paths = comment_reflow::rust_files(&args.paths).context("collecting Rust files")?;
    let config = comment_reflow::Config {
        width,
        include_normal_comments: !args.doc_comments_only,
    };

    let mut changed = Vec::new();

    for path in paths {
        let source =
            fs_err::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let reflowed = comment_reflow::reflow_source(&source, config)
            .with_context(|| format!("reflowing {}", path.display()))?;

        if reflowed != source {
            if args.write {
                fs_err::write(&path, reflowed)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            changed.push(path);
        }
    }

    if changed.is_empty() {
        return Ok(());
    }

    if args.write {
        eprintln!("reflowed comments in {} file(s)", changed.len());
        return Ok(());
    }

    for path in &changed {
        eprintln!("comments need reflow: {}", path.display());
    }

    let mode = if args.check { "--check" } else { "default check" };
    bail!(
        "{} file(s) need comment reflow ({mode}); run `cargo xtask fmt-comments --write`",
        changed.len()
    );
}

fn comment_width(explicit: Option<usize>) -> Result<usize> {
    if let Some(width) = explicit {
        return validate_width(width);
    }

    let source = match fs_err::read_to_string("rustfmt.toml") {
        Ok(source) => source,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(100),
        Err(err) => return Err(err).context("reading rustfmt.toml"),
    };

    let config =
        toml::from_str::<toml::Value>(&source).context("parsing rustfmt.toml for comment_width")?;
    let width = config
        .get("comment_width")
        .and_then(toml::Value::as_integer)
        .and_then(|width| usize::try_from(width).ok())
        .unwrap_or(100);

    validate_width(width)
}

fn validate_width(width: usize) -> Result<usize> {
    ensure!(width >= 20, "comment width must be at least 20 columns");
    Ok(width)
}
