mod changelog;
mod comment_reflow;

use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{ArgGroup, Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Repository maintenance tasks", name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate changelog metadata in pull request descriptions.
    #[command(subcommand)]
    Changelog(Changelog),

    /// Reflow safe Rust line-comment blocks.
    FmtComments(FmtCommentsArgs),
}

#[derive(Debug, Subcommand)]
enum Changelog {
    /// Verify changelog metadata in a pull request body.
    Verify {
        /// Markdown file containing the pull request body.
        #[arg(long)]
        pr_body_file: PathBuf,
    },

    /// Render release notes.
    Render(RenderArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["release_tag", "current"])
))]
struct RenderArgs {
    /// Release tag to render notes for.
    #[arg(long)]
    release_tag: Option<String>,

    /// Render notes for the current commit range since the latest stable release tag.
    #[arg(long)]
    current: bool,
}

impl Changelog {
    fn run(self) -> Result<()> {
        match self {
            Self::Verify { pr_body_file } => {
                let result = (|| {
                    let source = fs_err::read_to_string(&pr_body_file)
                        .with_context(|| format!("reading {}", pr_body_file.display()))?;

                    changelog::verify_pr_body(&source)
                })();

                result.inspect_err(|err| {
                    emit_github_error_annotation("Invalid changelog metadata", err);
                })
            },
            Self::Render(args) => {
                let notes = if args.current {
                    changelog::render_current_changelog()?
                } else {
                    let release_tag = args
                        .release_tag
                        .expect("clap requires either --release-tag or --current");
                    changelog::render_release_notes(&release_tag)?
                };
                let mut stdout = io::stdout().lock();
                stdout.write_all(notes.as_bytes())?;
                stdout.flush()?;
                Ok(())
            },
        }
    }
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

    /// Target total line width. Defaults to rustfmt's `comment_width`, or 100.
    #[arg(long)]
    width: Option<usize>,

    /// Path to the rustfmt config used to source `comment_width`.
    #[arg(long, default_value = ".config/rustfmt.toml")]
    rustfmt_config: PathBuf,

    /// Files or directories to process. Defaults to the repository tree.
    paths: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Changelog(command) => command.run(),
        Command::FmtComments(args) => run_fmt_comments(&args),
    }
}

fn emit_github_error_annotation(title: &str, err: &anyhow::Error) {
    if !std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true") {
        return;
    }

    let title = github_escape_property(title);
    let message = github_escape_data(&format!("{err:#}"));
    eprintln!("::error title={title}::{message}");
}

fn github_escape_property(value: &str) -> String {
    github_escape_data(value).replace(':', "%3A").replace(',', "%2C")
}

fn github_escape_data(value: &str) -> String {
    value.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn run_fmt_comments(args: &FmtCommentsArgs) -> Result<()> {
    let width = comment_width(args.width, &args.rustfmt_config)?;
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

    let config = toml::from_str::<toml::Value>(&source)
        .context("parsing rustfmt config for comment_width")?;
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
