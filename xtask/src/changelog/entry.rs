use std::cmp::Ordering;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use fs_err::PathExt;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Component {
    RpcApi,
    Node,
    Validator,
    NtxBuilder,
    RemoteProver,
    NetworkMonitor,
    Packaging,
    Docs,
    Internal,
}

impl Component {
    pub(super) const ALL: [Self; 9] = [
        Self::RpcApi,
        Self::Node,
        Self::Validator,
        Self::NtxBuilder,
        Self::RemoteProver,
        Self::NetworkMonitor,
        Self::Packaging,
        Self::Docs,
        Self::Internal,
    ];
}

impl fmt::Display for Component {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RpcApi => "RPC API",
            Self::Node => "Node",
            Self::Validator => "Validator",
            Self::NtxBuilder => "Network Transaction Builder",
            Self::RemoteProver => "Remote Prover",
            Self::NetworkMonitor => "Network Monitor",
            Self::Packaging => "Packaging",
            Self::Docs => "Docs",
            Self::Internal => "Internal",
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Category {
    Added,
    Changed,
    Deprecated,
    Removed,
    Fixed,
    Security,
    Performance,
}

impl Category {
    pub(super) const ALL: [Self; 7] = [
        Self::Added,
        Self::Changed,
        Self::Deprecated,
        Self::Removed,
        Self::Fixed,
        Self::Security,
        Self::Performance,
    ];
}

impl fmt::Display for Category {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Deprecated => "Deprecated",
            Self::Removed => "Removed",
            Self::Fixed => "Fixed",
            Self::Security => "Security",
            Self::Performance => "Performance",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Changeset {
    entries: Vec<ChangesetEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangesetEntry {
    component: Component,
    category: Category,
    #[serde(default)]
    breaking: bool,
    #[serde(default)]
    related_prs: Vec<u64>,
    summary: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct Entry {
    pub(super) source: PathBuf,
    pub(super) pr: u64,
    pub(super) related_prs: Vec<u64>,
    pub(super) component: Component,
    pub(super) category: Category,
    pub(super) breaking: bool,
    pub(super) summary: String,
}

pub(super) fn collect_entry_files(dir: &Path, version: Option<&str>) -> Result<Vec<PathBuf>> {
    if let Some(version) = version {
        let version_dir = dir.join(version);
        ensure!(
            version_dir.exists(),
            "changelog version directory does not exist: {}",
            version_dir.display()
        );
        return collect_version_files(&version_dir);
    }

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs_err::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let version = file_name_string(&path)?;
        validate_version(&version)
            .with_context(|| format!("invalid version directory {version}"))?;
        files.extend(collect_version_files(&path)?);
    }

    files.sort();
    Ok(files)
}

pub(super) fn load_version(dir: &Path, version: &str) -> Result<Vec<Entry>> {
    let version_dir = dir.join(version);
    ensure!(
        version_dir.exists(),
        "changelog version directory does not exist: {}",
        version_dir.display()
    );

    let files = collect_version_files(&version_dir)?;
    let mut entries = Vec::new();

    for file in files {
        validate_file_layout(&file, dir)?;
        entries.extend(load_file(&file)?);
    }

    entries.sort_by(compare_entries);
    Ok(entries)
}

pub(super) fn load_file(path: &Path) -> Result<Vec<Entry>> {
    let pr = pr_number(path)?;
    let source =
        fs_err::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let changeset = toml::from_str::<Changeset>(&source)
        .with_context(|| format!("parsing {}", path.display()))?;

    ensure!(
        !changeset.entries.is_empty(),
        "{} must contain at least one [[entries]] table",
        path.display()
    );

    changeset
        .entries
        .into_iter()
        .map(|entry| validate_entry(path, pr, entry))
        .collect()
}

pub(super) fn validate_file_layout(path: &Path, dir: &Path) -> Result<()> {
    ensure!(
        path.extension().and_then(|extension| extension.to_str()) == Some("toml"),
        "changelog entry files must use .toml extension, found {}",
        path.display()
    );

    pr_number(path)?;

    let absolute_dir = dir
        .fs_err_canonicalize()
        .with_context(|| format!("canonicalizing {}", dir.display()))?;
    let absolute_path = path
        .fs_err_canonicalize()
        .with_context(|| format!("canonicalizing {}", path.display()))?;
    let relative = absolute_path.strip_prefix(&absolute_dir).with_context(|| {
        format!("{} is not inside changelog directory {}", path.display(), dir.display())
    })?;

    let mut components = relative.components();
    let version = components
        .next()
        .context("changelog entry path is missing version directory")?
        .as_os_str()
        .to_str()
        .context("version directory is not valid UTF-8")?;
    validate_version(version)?;

    let file = components.next().context("changelog entry path is missing file name")?;
    ensure!(
        components.next().is_none(),
        "changelog entries must be direct children of changelog.d/<version>/, found {}",
        path.display()
    );
    ensure!(
        Path::new(file.as_os_str()).file_name() == path.file_name(),
        "invalid changelog entry path {}",
        path.display()
    );

    Ok(())
}

pub(super) fn validate_version(version: &str) -> Result<()> {
    let version = version
        .strip_prefix('v')
        .context("changelog version must start with 'v', for example v0.15.0")?;
    let parts = version.split('.').collect::<Vec<_>>();
    ensure!(
        parts.len() == 3 && parts.iter().all(|part| !part.is_empty()),
        "changelog version must use vMAJOR.MINOR.PATCH format"
    );
    ensure!(
        parts.iter().all(|part| part.chars().all(|char| char.is_ascii_digit())),
        "changelog version must use numeric MAJOR.MINOR.PATCH parts"
    );
    Ok(())
}

pub(super) fn validate_date(date: &str) -> Result<()> {
    let bytes = date.as_bytes();
    ensure!(
        bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[..4].iter().all(u8::is_ascii_digit)
            && bytes[5..7].iter().all(u8::is_ascii_digit)
            && bytes[8..].iter().all(u8::is_ascii_digit),
        "release date must use YYYY-MM-DD format"
    );
    Ok(())
}

fn collect_version_files(version_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in fs_err::read_dir(version_dir)
        .with_context(|| format!("reading {}", version_dir.display()))?
    {
        let entry = entry.with_context(|| format!("reading {}", version_dir.display()))?;
        let path = entry.path();

        if path.is_dir() {
            bail!("changelog entries must be files, found {}", path.display());
        }

        ensure!(
            path.extension().and_then(|extension| extension.to_str()) == Some("toml"),
            "changelog entry files must use .toml extension, found {}",
            path.display()
        );

        files.push(path);
    }

    files.sort();
    Ok(files)
}

fn validate_entry(path: &Path, pr: u64, entry: ChangesetEntry) -> Result<Entry> {
    let ChangesetEntry {
        component,
        category,
        breaking,
        related_prs,
        summary,
    } = entry;
    let summary = summary.trim();

    ensure!(!summary.is_empty(), "{} has an empty changelog summary", path.display());
    ensure!(!summary.contains('\n'), "{} summary must be a single line", path.display());
    ensure!(
        component != Component::Internal || !breaking,
        "{} uses breaking = true for an internal entry",
        path.display()
    );
    validate_related_prs(path, pr, &related_prs)?;

    Ok(Entry {
        source: path.to_path_buf(),
        pr,
        related_prs,
        component,
        category,
        breaking,
        summary: summary.to_owned(),
    })
}

fn validate_related_prs(path: &Path, pr: u64, related_prs: &[u64]) -> Result<()> {
    for related_pr in related_prs {
        ensure!(
            *related_pr > 0,
            "{} has a related PR number that is not greater than zero",
            path.display()
        );
        ensure!(
            *related_pr != pr,
            "{} lists its filename PR number in `related_prs`",
            path.display()
        );
    }

    let mut sorted = related_prs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    ensure!(
        sorted.len() == related_prs.len(),
        "{} has duplicate PR numbers in `related_prs`",
        path.display()
    );

    Ok(())
}

fn pr_number(path: &Path) -> Result<u64> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .with_context(|| format!("{} has no valid file stem", path.display()))?;
    let digit_count = stem.chars().take_while(char::is_ascii_digit).count();
    ensure!(digit_count > 0, "{} must start with a pull request number", path.display());

    if digit_count < stem.len() {
        ensure!(
            stem.as_bytes()[digit_count] == b'-',
            "{} optional slug must be separated from the pull request number with '-'",
            path.display()
        );
    }

    let pr = stem[..digit_count]
        .parse::<u64>()
        .with_context(|| format!("parsing pull request number from {}", path.display()))?;
    ensure!(pr > 0, "{} pull request number must be greater than zero", path.display());

    Ok(pr)
}

fn compare_entries(left: &Entry, right: &Entry) -> Ordering {
    (
        left.component,
        !left.breaking,
        left.category,
        left.pr,
        &left.summary,
        &left.source,
    )
        .cmp(&(
            right.component,
            !right.breaking,
            right.category,
            right.pr,
            &right.summary,
            &right.source,
        ))
}

fn file_name_string(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|file_name| file_name.to_str())
        .map(str::to_owned)
        .with_context(|| format!("{} has no valid file name", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pr_number_with_optional_slug() {
        assert_eq!(pr_number(Path::new("changelog.d/v0.15.0/2056.toml")).unwrap(), 2056);
        assert_eq!(
            pr_number(Path::new("changelog.d/v0.15.0/2056-required-range.toml")).unwrap(),
            2056
        );
        assert!(pr_number(Path::new("changelog.d/v0.15.0/2056.required-range.toml")).is_err());
    }

    #[test]
    fn rejects_unknown_component() {
        let source = r#"
[[entries]]
component = "unknown"
category = "added"
breaking = false
summary = "Added something."
"#;

        assert!(toml::from_str::<Changeset>(source).is_err());
    }

    #[test]
    fn defaults_breaking_to_false() {
        let source = r#"
[[entries]]
component = "rpc-api"
category = "added"
summary = "Added a response field."
"#;

        let changeset = toml::from_str::<Changeset>(source).unwrap();

        assert!(!changeset.entries[0].breaking);
    }

    #[test]
    fn rejects_breaking_internal_entry() {
        let entry = ChangesetEntry {
            component: Component::Internal,
            category: Category::Changed,
            breaking: true,
            related_prs: Vec::new(),
            summary: "Changed an internal workflow.".to_owned(),
        };

        assert!(validate_entry(Path::new("changelog.d/v0.15.0/1.toml"), 1, entry).is_err());
    }

    #[test]
    fn rejects_empty_summary() {
        let entry = ChangesetEntry {
            component: Component::RpcApi,
            category: Category::Added,
            breaking: false,
            related_prs: Vec::new(),
            summary: "   ".to_owned(),
        };

        assert!(validate_entry(Path::new("changelog.d/v0.15.0/1.toml"), 1, entry).is_err());
    }

    #[test]
    fn rejects_related_pr_matching_filename_pr() {
        let entry = ChangesetEntry {
            component: Component::RpcApi,
            category: Category::Changed,
            breaking: false,
            related_prs: vec![1],
            summary: "Changed a response field.".to_owned(),
        };

        assert!(validate_entry(Path::new("changelog.d/v0.15.0/1.toml"), 1, entry).is_err());
    }

    #[test]
    fn rejects_duplicate_related_prs() {
        let entry = ChangesetEntry {
            component: Component::RpcApi,
            category: Category::Changed,
            breaking: false,
            related_prs: vec![2, 2],
            summary: "Changed a response field.".to_owned(),
        };

        assert!(validate_entry(Path::new("changelog.d/v0.15.0/1.toml"), 1, entry).is_err());
    }
}
