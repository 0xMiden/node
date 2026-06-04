mod heuristics;
mod report;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use self::heuristics::{Trigger, classify_path, needs_dependency_diff};
use self::report::CheckResult;
use super::CHANGELOG_DIR;
use super::entry::{load_file, validate_file_layout};

#[derive(Debug, ClapArgs)]
pub(super) struct CiCheck {
    /// Git base revision to compare against, for example origin/main.
    #[arg(long)]
    base: String,

    /// Pull request number, used only for reporting.
    #[arg(long)]
    pr: u64,

    /// Changelog entry root directory.
    #[arg(long, default_value = CHANGELOG_DIR)]
    dir: PathBuf,

    /// Markdown report path. Defaults to stdout.
    #[arg(long)]
    report: Option<PathBuf>,

    /// Whether the pull request has the "no changelog" label.
    #[arg(long)]
    no_changelog_label: bool,
}

impl CiCheck {
    pub(super) fn run(&self) -> Result<()> {
        let changed_files = changed_files(&self.base)?;
        let triggers = collect_triggers(&self.base, &changed_files)?;
        let changelog_files = changed_files
            .iter()
            .filter(|path| path.starts_with(&self.dir))
            .cloned()
            .collect::<Vec<_>>();
        let validation_errors = validate_changed_changelog_files(&self.dir, &changelog_files);

        let result = CheckResult {
            pr: self.pr,
            no_changelog_label: self.no_changelog_label,
            triggers,
            changelog_files,
            validation_errors,
        };
        let report = result.render();
        write_report(self.report.as_deref(), &report)?;

        if !result.validation_errors.is_empty() {
            bail!("changed changelog entries failed validation");
        }

        if result.requires_changelog()
            && !result.has_changelog_change()
            && !result.no_changelog_label
        {
            bail!("a changelog entry is likely required");
        }

        Ok(())
    }
}

fn collect_triggers(base: &str, changed_files: &[PathBuf]) -> Result<Vec<Trigger>> {
    let mut triggers = Vec::new();

    for path in changed_files {
        let file_text = read_existing_file(path)?;
        let diff_text = if needs_dependency_diff(path) {
            Some(diff_for_path(base, path)?)
        } else {
            None
        };

        triggers.extend(classify_path(path, file_text.as_deref(), diff_text.as_deref()));
    }

    triggers.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.details.cmp(&right.details))
    });
    triggers.dedup();

    Ok(triggers)
}

fn validate_changed_changelog_files(dir: &Path, changed_files: &[PathBuf]) -> Vec<String> {
    changed_files
        .iter()
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("toml"))
        .filter(|path| path.exists())
        .filter_map(|path| {
            validate_file_layout(path, dir)
                .and_then(|()| load_file(path).map(|_| ()))
                .err()
                .map(|error| format!("`{}`: {error:#}", path.display()))
        })
        .collect()
}

fn changed_files(base: &str) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", base, "HEAD"])
        .output()
        .with_context(|| format!("running git diff against {base}"))?;
    if !output.status.success() {
        bail!("git diff failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(PathBuf::from)
        .collect())
}

fn diff_for_path(base: &str, path: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("diff")
        .arg("--unified=3")
        .arg(base)
        .arg("HEAD")
        .arg("--")
        .arg(path)
        .output()
        .with_context(|| format!("running git diff for {}", path.display()))?;
    if !output.status.success() {
        bail!(
            "git diff failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn read_existing_file(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    fs_err::read_to_string(path)
        .map(Some)
        .with_context(|| format!("reading {}", path.display()))
}

fn write_report(path: Option<&Path>, report: &str) -> Result<()> {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs_err::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        fs_err::write(path, report).with_context(|| format!("writing {}", path.display()))?;
    } else {
        print!("{report}");
    }

    Ok(())
}
