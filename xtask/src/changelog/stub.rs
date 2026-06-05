use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;

use super::CHANGELOG_DIR;
use super::entry::validate_version;

#[derive(Debug, ClapArgs)]
pub(super) struct Stub {
    /// Changelog entry root directory.
    #[arg(long, default_value = CHANGELOG_DIR)]
    dir: PathBuf,

    /// Version directory for the new entry. Defaults to the latest version directory.
    #[arg(short, long)]
    version: Option<String>,

    /// Pull request number used as the entry filename prefix. Defaults to "stub".
    #[arg(short, long)]
    pr: Option<u64>,

    /// Optional filename slug appended after the pull request number.
    #[arg(short, long)]
    slug: Option<String>,

    /// Optional component value for the generated entry.
    #[arg(short = 'm', long)]
    component: Option<String>,

    /// Optional category value for the generated entry.
    #[arg(short = 'c', long)]
    category: Option<String>,
}

impl Stub {
    pub(super) fn run(&self) -> Result<()> {
        let version = match &self.version {
            Some(version) => {
                validate_version(version)?;
                version.clone()
            },
            None => latest_version(&self.dir)?,
        };

        if let Some(pr) = self.pr {
            validate_pr(pr)?;
        }
        if let Some(slug) = &self.slug {
            validate_slug(slug)?;
        }
        if let Some(component) = &self.component {
            validate_allowed_value("component", component, COMPONENTS)?;
        }
        if let Some(category) = &self.category {
            validate_allowed_value("category", category, CATEGORIES)?;
        }

        let version_dir = self.dir.join(&version);
        fs_err::create_dir_all(&version_dir)
            .with_context(|| format!("creating {}", version_dir.display()))?;

        let path = version_dir.join(entry_file_name(self.pr, self.slug.as_deref()));
        ensure!(!path.exists(), "{} already exists", path.display());

        fs_err::write(&path, stub_entry(self.component.as_deref(), self.category.as_deref()))
            .with_context(|| format!("writing {}", path.display()))?;

        eprintln!("created {}", path.display());

        Ok(())
    }
}

const COMPONENTS: &[&str] = &[
    "rpc-api",
    "node",
    "validator",
    "ntx-builder",
    "remote-prover",
    "network-monitor",
    "packaging",
    "docs",
    "internal",
];
const CATEGORIES: &[&str] =
    &["added", "changed", "deprecated", "removed", "fixed", "security", "performance"];

fn validate_pr(pr: u64) -> Result<()> {
    ensure!(pr > 0, "pull request number must be greater than zero");
    Ok(())
}

fn validate_slug(slug: &str) -> Result<()> {
    ensure!(!slug.is_empty(), "changelog entry slug cannot be empty");
    ensure!(
        slug.chars()
            .all(|char| char.is_ascii_lowercase() || char.is_ascii_digit() || char == '-'),
        "changelog entry slug must use lowercase ASCII letters, digits, and '-'"
    );
    ensure!(!slug.starts_with('-'), "changelog entry slug cannot start with '-'");
    ensure!(!slug.ends_with('-'), "changelog entry slug cannot end with '-'");
    ensure!(!slug.contains("--"), "changelog entry slug cannot contain consecutive '-'");

    Ok(())
}

fn validate_allowed_value(kind: &str, value: &str, allowed: &[&str]) -> Result<()> {
    ensure!(allowed.contains(&value), "{kind} must be one of: {}", allowed.join(", "));
    Ok(())
}

fn entry_file_name(pr: Option<u64>, slug: Option<&str>) -> String {
    let pr = pr.map_or_else(|| "stub".to_owned(), |pr| pr.to_string());
    match slug {
        Some(slug) => format!("{pr}-{slug}.toml"),
        None => format!("{pr}.toml"),
    }
}

fn latest_version(dir: &Path) -> Result<String> {
    ensure!(dir.exists(), "changelog entry root directory does not exist: {}", dir.display());

    let mut versions = Vec::new();
    for entry in fs_err::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let version = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .map(str::to_owned)
            .with_context(|| format!("{} has no valid file name", path.display()))?;
        validate_version(&version)
            .with_context(|| format!("invalid version directory {version}"))?;
        versions.push((VersionKey::parse(&version)?, version));
    }

    versions.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    versions
        .pop()
        .map(|(_, version)| version)
        .with_context(|| format!("no changelog version directories found in {}", dir.display()))
}

#[derive(Debug, Eq, PartialEq)]
struct VersionKey {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<Vec<PrereleaseId>>,
}

impl VersionKey {
    fn parse(version: &str) -> Result<Self> {
        let version = version
            .strip_prefix('v')
            .context("changelog version must start with 'v', for example v0.15.0")?;
        let (version, prerelease) = match version.split_once('-') {
            Some((version, prerelease)) => (version, Some(prerelease)),
            None => (version, None),
        };
        let mut parts = version.split('.');
        let major = parse_version_part(parts.next(), "major")?;
        let minor = parse_version_part(parts.next(), "minor")?;
        let patch = parse_version_part(parts.next(), "patch")?;
        ensure!(parts.next().is_none(), "changelog version has too many parts");

        let prerelease = prerelease
            .map(|prerelease| {
                prerelease.split('.').map(PrereleaseId::parse).collect::<Result<Vec<_>>>()
            })
            .transpose()?;

        Ok(Self { major, minor, patch, prerelease })
    }
}

impl Ord for VersionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| {
                compare_prerelease(self.prerelease.as_deref(), other.prerelease.as_deref())
            })
    }
}

impl PartialOrd for VersionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Eq, PartialEq)]
enum PrereleaseId {
    Numeric(u64),
    Text(String),
}

impl PrereleaseId {
    fn parse(value: &str) -> Result<Self> {
        ensure!(!value.is_empty(), "prerelease identifier cannot be empty");

        if value.chars().all(|char| char.is_ascii_digit()) {
            Ok(Self::Numeric(value.parse()?))
        } else {
            Ok(Self::Text(value.to_owned()))
        }
    }
}

impl Ord for PrereleaseId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => left.cmp(right),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for PrereleaseId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_version_part(part: Option<&str>, name: &str) -> Result<u64> {
    part.with_context(|| format!("missing {name} version part"))?
        .parse()
        .with_context(|| format!("invalid {name} version part"))
}

fn compare_prerelease(left: Option<&[PrereleaseId]>, right: Option<&[PrereleaseId]>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => compare_prerelease_ids(left, right),
    }
}

fn compare_prerelease_ids(left: &[PrereleaseId], right: &[PrereleaseId]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        match left.cmp(right) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
    }

    left.len().cmp(&right.len())
}

fn stub_entry(component: Option<&str>, category: Option<&str>) -> String {
    let component = component.unwrap_or("<component>");
    let category = category.unwrap_or("<category>");

    format!(
        r#"[[entries]]
# Choose one:
component = "{component}"
# components = ["<component>", "<component>"]
category = "{category}"
# breaking = true
summary = "<summary>"
# related_prs = []
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_entry_file_name() {
        assert_eq!(entry_file_name(Some(2199), None), "2199.toml");
        assert_eq!(
            entry_file_name(Some(2199), Some("trace-export-tls")),
            "2199-trace-export-tls.toml"
        );
        assert_eq!(entry_file_name(None, None), "stub.toml");
        assert_eq!(entry_file_name(None, Some("trace-export-tls")), "stub-trace-export-tls.toml");
    }

    #[test]
    fn validates_entry_slug() {
        assert!(validate_slug("trace-export-tls").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("Trace-Export").is_err());
        assert!(validate_slug("-trace-export").is_err());
        assert!(validate_slug("trace-export-").is_err());
        assert!(validate_slug("trace--export").is_err());
        assert!(validate_slug("trace/export").is_err());
    }

    #[test]
    fn validates_stub_values() {
        assert!(validate_allowed_value("component", "ntx-builder", COMPONENTS).is_ok());
        assert!(validate_allowed_value("category", "fixed", CATEGORIES).is_ok());
        assert!(validate_allowed_value("component", "unknown", COMPONENTS).is_err());
        assert!(validate_allowed_value("category", "unknown", CATEGORIES).is_err());
    }

    #[test]
    fn stub_is_toml_with_placeholders() {
        let source = stub_entry(None, None);

        assert!(source.contains("[[entries]]"));
        assert!(source.contains("component = \"<component>\""));
        assert!(source.contains("category = \"<category>\""));
        assert!(source.contains("summary = \"<summary>\""));
        assert!(toml::from_str::<toml::Table>(&source).is_ok());
    }

    #[test]
    fn stub_can_fill_component_and_category() {
        let source = stub_entry(Some("ntx-builder"), Some("added"));

        assert!(source.contains("component = \"ntx-builder\""));
        assert!(source.contains("category = \"added\""));
        assert!(toml::from_str::<toml::Table>(&source).is_ok());
    }

    #[test]
    fn sorts_version_keys() {
        let mut versions =
            ["v0.15.0-rc.1", "v0.15.0", "v0.16.0-rc.0", "v0.15.0-rc.10", "v0.15.0-rc.2"]
                .map(|version| VersionKey::parse(version).unwrap());
        versions.sort();

        assert!(versions[0] < versions[1]);
        assert!(versions[1] < versions[2]);
        assert!(versions[2] < versions[3]);
        assert!(versions[3] < versions[4]);
    }
}
