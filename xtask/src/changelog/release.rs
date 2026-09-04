use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use semver::Version;
use serde::Deserialize;

use super::pr::{self, ChangelogDocument};
use super::{
    Database,
    DatabaseMigrationUpdate,
    InvalidChangelogEntry,
    InvalidChangelogSource,
    ProtocolUpdate,
    ReleaseNoteEntry,
    RustMsrvUpdate,
};

pub(super) struct ChangelogEntries {
    pub(super) protocol_update: Option<ProtocolUpdate>,
    pub(super) rust_msrv_update: Option<RustMsrvUpdate>,
    pub(super) database_migration_updates: Vec<DatabaseMigrationUpdate>,
    pub(super) entries: Vec<ReleaseNoteEntry>,
    pub(super) invalid_entries: Vec<InvalidChangelogEntry>,
}

pub(super) struct CurrentChangelog {
    pub(super) title: String,
    pub(super) protocol_update: Option<ProtocolUpdate>,
    pub(super) rust_msrv_update: Option<RustMsrvUpdate>,
    pub(super) database_migration_updates: Vec<DatabaseMigrationUpdate>,
    pub(super) entries: Vec<ReleaseNoteEntry>,
    pub(super) invalid_entries: Vec<InvalidChangelogEntry>,
}

pub(super) fn release_changelog_entries(release_tag: &str) -> Result<ChangelogEntries> {
    ensure!(!release_tag.trim().is_empty(), "release tag must not be empty");

    let release = ReleaseTag::parse(release_tag)?;
    let tag_commit = format!("refs/tags/{release_tag}^{{commit}}");
    let release_commit = git_output(&["rev-parse", "--verify", &tag_commit])
        .with_context(|| format!("resolving release tag {release_tag}"))?;
    let release_commit = release_commit.trim();

    ensure!(
        !release_commit.is_empty(),
        "release tag {release_tag} did not resolve to a commit"
    );

    let previous_release_tag = previous_release_tag(&release, release_commit)?;
    let previous_release_ref = format!("refs/tags/{previous_release_tag}");
    let release_ref = format!("refs/tags/{release_tag}");
    let commits = commits_since_tag(&previous_release_tag, &release_ref)?;
    ensure!(
        !commits.is_empty(),
        "release range refs/tags/{previous_release_tag}..refs/tags/{release_tag} contains no commits"
    );
    let repo = github_repo()?;
    let pull_requests = pull_requests_for_commits(&repo, &commits)?;
    let mut changelog = changelog_entries_for_pull_requests(&repo, &pull_requests.pull_requests);
    changelog.invalid_entries.extend(pull_requests.invalid_entries);
    changelog.protocol_update = protocol_update(&previous_release_ref, &release_ref)?;
    changelog.rust_msrv_update = rust_msrv_update(&previous_release_ref, &release_ref)?;
    changelog.database_migration_updates =
        database_migration_updates(&previous_release_ref, &release_ref)?;

    Ok(changelog)
}

pub(super) fn current_changelog_entries() -> Result<CurrentChangelog> {
    let head_commit =
        git_output(&["rev-parse", "--verify", "HEAD^{commit}"]).context("resolving HEAD")?;
    let head_commit = head_commit.trim();

    ensure!(!head_commit.is_empty(), "HEAD did not resolve to a commit");

    let previous_stable_tag = latest_stable_tag(head_commit)?;
    let commits = commits_since_tag(&previous_stable_tag, "HEAD")?;

    if commits.is_empty() {
        return Ok(CurrentChangelog {
            title: format!("Changes since {previous_stable_tag}"),
            protocol_update: None,
            rust_msrv_update: None,
            database_migration_updates: Vec::new(),
            entries: Vec::new(),
            invalid_entries: Vec::new(),
        });
    }

    let repo = github_repo()?;
    let pull_requests = pull_requests_for_commits(&repo, &commits)?;
    let mut changelog = changelog_entries_for_pull_requests(&repo, &pull_requests.pull_requests);
    changelog.invalid_entries.extend(pull_requests.invalid_entries);

    Ok(CurrentChangelog {
        title: format!("Changes since {previous_stable_tag}"),
        protocol_update: protocol_update(&format!("refs/tags/{previous_stable_tag}"), "HEAD")?,
        rust_msrv_update: rust_msrv_update(&format!("refs/tags/{previous_stable_tag}"), "HEAD")?,
        database_migration_updates: database_migration_updates(
            &format!("refs/tags/{previous_stable_tag}"),
            "HEAD",
        )?,
        entries: changelog.entries,
        invalid_entries: changelog.invalid_entries,
    })
}

#[derive(Debug)]
struct ReleaseTag {
    version: Version,
}

struct PullRequests {
    pull_requests: Vec<AssociatedPullRequest>,
    invalid_entries: Vec<InvalidChangelogEntry>,
}

struct AssociatedPullRequest {
    number: u64,
    order: usize,
}

enum CommitPullRequests {
    Found(Vec<u64>),
    CommitNotFound,
}

impl ReleaseTag {
    fn parse(tag: &str) -> Result<Self> {
        let Some(version) = tag.strip_prefix('v') else {
            bail!("release tags must look like v1.2.3 or v1.2.3-rc.1");
        };

        let Ok(version) = Version::parse(version) else {
            bail!("release tags must look like v1.2.3 or v1.2.3-rc.1");
        };

        ensure!(version.build.is_empty(), "release tags must look like v1.2.3 or v1.2.3-rc.1");

        Ok(Self { version })
    }
}

fn previous_release_tag(release: &ReleaseTag, release_commit: &str) -> Result<String> {
    let tags = release_tags_merged_into(release_commit)?;

    if let Some(tag) = previous_release_tag_from(release, &tags) {
        return Ok(tag.to_owned());
    }

    let release_kind = if release.version.pre.is_empty() {
        "stable release"
    } else {
        "release"
    };
    bail!("could not find a previous {release_kind} tag before v{}", release.version);
}

fn latest_stable_tag(release_commit: &str) -> Result<String> {
    release_tags_merged_into(release_commit)?
        .into_iter()
        .filter(|(_tag, version)| version.pre.is_empty())
        .max_by(|(_tag_a, version_a), (_tag_b, version_b)| version_a.cmp(version_b))
        .map(|(tag, _version)| tag)
        .context("could not find a stable release tag reachable from HEAD")
}

fn previous_release_tag_from<'a>(
    release: &ReleaseTag,
    tags: &'a [(String, Version)],
) -> Option<&'a str> {
    let stable_only = release.version.pre.is_empty();

    tags.iter()
        .filter(|(_tag, version)| version < &release.version)
        .filter(|(_tag, version)| !stable_only || version.pre.is_empty())
        .max_by(|(_tag_a, version_a), (_tag_b, version_b)| version_a.cmp(version_b))
        .map(|(tag, _version)| tag.as_str())
}

fn release_tags_merged_into(commit: &str) -> Result<Vec<(String, Version)>> {
    let tags = git_output(&["tag", "--merged", commit, "--list", "v*", "--sort=-v:refname"])
        .context("listing release tags")?;

    Ok(tags
        .lines()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .filter_map(|tag| {
            ReleaseTag::parse(tag).ok().map(|release| (tag.to_owned(), release.version))
        })
        .collect())
}

fn commits_since_tag(previous_stable_tag: &str, end_ref: &str) -> Result<Vec<String>> {
    let range = format!("refs/tags/{previous_stable_tag}..{end_ref}");
    let commits = git_output(&["log", "--reverse", "--format=%H", &range])
        .with_context(|| format!("listing commits in {range}"))?;

    Ok(commits
        .lines()
        .map(str::trim)
        .filter(|commit| !commit.is_empty())
        .map(str::to_owned)
        .collect())
}

fn protocol_update(previous_ref: &str, current_ref: &str) -> Result<Option<ProtocolUpdate>> {
    let previous_lockfile = lockfile_at(previous_ref)?;
    let current_lockfile = lockfile_at(current_ref)?;

    protocol_update_from_lockfiles(&previous_lockfile, &current_lockfile)
}

fn lockfile_at(git_ref: &str) -> Result<String> {
    let object = format!("{git_ref}:Cargo.lock");
    git_output(&["show", &object]).with_context(|| format!("reading Cargo.lock at {git_ref}"))
}

fn protocol_update_from_lockfiles(
    previous_lockfile: &str,
    current_lockfile: &str,
) -> Result<Option<ProtocolUpdate>> {
    let previous = protocol_version_from_lockfile(previous_lockfile)
        .context("reading the previous miden-protocol version")?;
    let current = protocol_version_from_lockfile(current_lockfile)
        .context("reading the current miden-protocol version")?;

    Ok((previous != current).then_some(ProtocolUpdate { previous, current }))
}

fn protocol_version_from_lockfile(source: &str) -> Result<Version> {
    #[derive(Deserialize)]
    struct Lockfile {
        package: Vec<Package>,
    }

    #[derive(Deserialize)]
    struct Package {
        name: String,
        version: String,
    }

    let lockfile = toml::from_str::<Lockfile>(source).context("parsing Cargo.lock as TOML")?;
    let versions = lockfile
        .package
        .into_iter()
        .filter(|package| package.name == "miden-protocol")
        .map(|package| package.version)
        .collect::<Vec<_>>();

    ensure!(
        versions.len() == 1,
        "expected one miden-protocol package in Cargo.lock, found {}",
        versions.len()
    );

    Version::parse(&versions[0]).context("parsing the miden-protocol version")
}

fn rust_msrv_update(previous_ref: &str, current_ref: &str) -> Result<Option<RustMsrvUpdate>> {
    let previous_manifest = manifest_at(previous_ref)?;
    let current_manifest = manifest_at(current_ref)?;

    rust_msrv_update_from_manifests(&previous_manifest, &current_manifest)
}

fn manifest_at(git_ref: &str) -> Result<String> {
    let object = format!("{git_ref}:Cargo.toml");
    git_output(&["show", &object]).with_context(|| format!("reading Cargo.toml at {git_ref}"))
}

fn rust_msrv_update_from_manifests(
    previous_manifest: &str,
    current_manifest: &str,
) -> Result<Option<RustMsrvUpdate>> {
    let previous =
        rust_msrv_from_manifest(previous_manifest).context("reading the previous Rust MSRV")?;
    let current =
        rust_msrv_from_manifest(current_manifest).context("reading the current Rust MSRV")?;

    Ok((previous != current).then_some(RustMsrvUpdate { previous, current }))
}

fn rust_msrv_from_manifest(source: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Manifest {
        workspace: Workspace,
    }

    #[derive(Deserialize)]
    struct Workspace {
        package: WorkspacePackage,
    }

    #[derive(Deserialize)]
    struct WorkspacePackage {
        #[serde(rename = "rust-version")]
        rust_version: String,
    }

    let manifest = toml::from_str::<Manifest>(source).context("parsing Cargo.toml as TOML")?;
    ensure!(!manifest.workspace.package.rust_version.trim().is_empty(), "Rust MSRV is empty");

    Ok(manifest.workspace.package.rust_version)
}

fn database_migration_updates(
    previous_ref: &str,
    current_ref: &str,
) -> Result<Vec<DatabaseMigrationUpdate>> {
    let previous_tree = migration_tree_at(previous_ref)?;
    let current_tree = migration_tree_at(current_ref)?;

    Ok(database_migration_updates_from_trees(&previous_tree, &current_tree))
}

fn migration_tree_at(git_ref: &str) -> Result<String> {
    git_output(&[
        "ls-tree",
        "-r",
        "--name-only",
        git_ref,
        "--",
        Database::Store.path(),
        Database::Validator.path(),
        Database::NtxBuilder.path(),
    ])
    .with_context(|| format!("listing database migrations at {git_ref}"))
}

fn database_migration_updates_from_trees(
    previous_tree: &str,
    current_tree: &str,
) -> Vec<DatabaseMigrationUpdate> {
    Database::ALL
        .into_iter()
        .filter_map(|database| {
            let previous = migration_version(previous_tree, database);
            let current = migration_version(current_tree, database);

            (current > previous).then_some(DatabaseMigrationUpdate { database, previous, current })
        })
        .collect()
}

fn migration_version(tree: &str, database: Database) -> u16 {
    tree.lines()
        .filter_map(|path| migration_prefix(path, database))
        .max()
        .unwrap_or(0)
}

fn migration_prefix(path: &str, database: Database) -> Option<u16> {
    let relative = path.strip_prefix(database.path())?.strip_prefix('/')?;
    let file_name = if let Some(retired) = relative.strip_prefix("retired/") {
        if retired.contains('/') || Path::new(retired).extension() != Some(OsStr::new("sql")) {
            return None;
        }
        retired
    } else {
        let extension = Path::new(relative).extension();
        if relative.contains('/')
            || !(extension == Some(OsStr::new("sql")) || extension == Some(OsStr::new("rs")))
        {
            return None;
        }
        relative
    };
    let (prefix, _name) = file_name.split_once('_')?;

    if prefix.len() != 3 || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    prefix.parse().ok()
}

impl Database {
    const ALL: [Self; 3] = [Self::Store, Self::Validator, Self::NtxBuilder];

    const fn path(self) -> &'static str {
        match self {
            Self::Store => "crates/store/src/db/migrations",
            Self::Validator => "bin/validator/src/db/migrations",
            Self::NtxBuilder => "bin/ntx-builder/src/db/migrations",
        }
    }
}

fn github_repo() -> Result<String> {
    if let Ok(repo) = env::var("GITHUB_REPOSITORY") {
        let repo = repo.trim();

        if !repo.is_empty() {
            return Ok(repo.to_owned());
        }
    }

    let mut command = Command::new("gh");
    command.args(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]);
    let repo = command_output(&mut command).context("resolving GitHub repository")?;
    let repo = repo.trim();

    ensure!(!repo.is_empty(), "could not resolve GitHub repository");

    Ok(repo.to_owned())
}

fn pull_requests_for_commits(repo: &str, commits: &[String]) -> Result<PullRequests> {
    pull_requests_for_commits_with(repo, commits, pull_requests_for_commit)
}

fn pull_requests_for_commits_with<F>(
    repo: &str,
    commits: &[String],
    mut pull_requests_for_commit: F,
) -> Result<PullRequests>
where
    F: FnMut(&str, &str) -> Result<CommitPullRequests>,
{
    let mut pull_requests = Vec::new();
    let mut invalid_entries = Vec::new();

    for (order, commit) in commits.iter().enumerate() {
        let commit_pull_requests = pull_requests_for_commit(repo, commit)
            .with_context(|| format!("fetching pull requests associated with commit {commit}"))?;

        let CommitPullRequests::Found(commit_pull_requests) = commit_pull_requests else {
            invalid_entries.push(InvalidChangelogEntry {
                source: InvalidChangelogSource::Commit(commit.clone()),
                reason: format!("commit was not found in GitHub repository {repo}"),
                order,
            });
            continue;
        };

        if commit_pull_requests.is_empty() {
            invalid_entries.push(InvalidChangelogEntry {
                source: InvalidChangelogSource::Commit(commit.clone()),
                reason: "no associated pull request".to_owned(),
                order,
            });
            continue;
        }

        for pull_request in commit_pull_requests {
            if !pull_requests
                .iter()
                .any(|entry: &AssociatedPullRequest| entry.number == pull_request)
            {
                pull_requests.push(AssociatedPullRequest { number: pull_request, order });
            }
        }
    }

    Ok(PullRequests { pull_requests, invalid_entries })
}

fn pull_requests_for_commit(repo: &str, commit: &str) -> Result<CommitPullRequests> {
    let endpoint = format!("repos/{repo}/commits/{commit}/pulls");
    let mut command = Command::new("gh");
    command.args([
        "api",
        "-H",
        "Accept: application/vnd.github+json",
        &endpoint,
        "--jq",
        ".[].number",
    ]);

    let output = gh_api_output(&mut command)?;
    let Some(output) = output else {
        return Ok(CommitPullRequests::CommitNotFound);
    };

    let pull_requests = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<u64>()
                .with_context(|| format!("parsing pull request number `{line}`"))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CommitPullRequests::Found(pull_requests))
}

fn changelog_entries_for_pull_requests(
    repo: &str,
    pull_requests: &[AssociatedPullRequest],
) -> ChangelogEntries {
    changelog_entries_for_pull_requests_with(repo, pull_requests, pull_request_body)
}

fn changelog_entries_for_pull_requests_with<F>(
    repo: &str,
    pull_requests: &[AssociatedPullRequest],
    mut pull_request_body: F,
) -> ChangelogEntries
where
    F: FnMut(&str, u64) -> Result<String>,
{
    let mut entries = Vec::new();
    let mut invalid_entries = Vec::new();

    for pull_request in pull_requests {
        let body = match pull_request_body(repo, pull_request.number) {
            Ok(body) => body,
            Err(err) => {
                eprintln!(
                    "warning: could not fetch pull request #{} body: {err:#}",
                    pull_request.number
                );
                invalid_entries.push(InvalidChangelogEntry {
                    source: InvalidChangelogSource::PullRequest(pull_request.number),
                    reason: "pull request body could not be fetched".to_owned(),
                    order: pull_request.order,
                });
                continue;
            },
        };

        let document = match pr::changelog_document_from_pr_body(&body) {
            Ok(document) => document,
            Err(err) => {
                invalid_entries.push(InvalidChangelogEntry {
                    source: InvalidChangelogSource::PullRequest(pull_request.number),
                    reason: normalize_description(&format!("{err:#}")),
                    order: pull_request.order,
                });
                continue;
            },
        };

        let ChangelogDocument::Entries(pr_entries) = document else {
            continue;
        };

        for entry in pr_entries {
            entries.push(ReleaseNoteEntry {
                pr_number: pull_request.number,
                scope: entry.scope,
                impact: entry.impact,
                description: normalize_description(&entry.description),
                order: pull_request.order,
            });
        }
    }

    ChangelogEntries {
        protocol_update: None,
        rust_msrv_update: None,
        database_migration_updates: Vec::new(),
        entries,
        invalid_entries,
    }
}

fn pull_request_body(repo: &str, pull_request: u64) -> Result<String> {
    let pull_request = pull_request.to_string();
    let mut command = Command::new("gh");
    command.args(["pr", "view", &pull_request, "--repo", repo, "--json", "body", "--jq", ".body"]);

    command_output(&mut command)
}

fn git_output(args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command.args(args);
    command_output(&mut command)
}

fn command_output(command: &mut Command) -> Result<String> {
    let command_display = format!("{command:?}");
    let output = command.output().with_context(|| format!("running `{command_display}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "command `{command_display}` failed with status {}: {}",
            output.status,
            stderr.trim()
        );
    }

    String::from_utf8(output.stdout)
        .with_context(|| format!("command `{command_display}` printed non-UTF-8 output"))
}

fn gh_api_output(command: &mut Command) -> Result<Option<String>> {
    let command_display = format!("{command:?}");
    let output = command.output().with_context(|| format!("running `{command_display}`"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr.contains("No commit found for SHA") {
            return Ok(None);
        }

        bail!(
            "command `{command_display}` failed with status {}: {}",
            output.status,
            stderr.trim()
        );
    }

    String::from_utf8(output.stdout)
        .map(Some)
        .with_context(|| format!("command `{command_display}` printed non-UTF-8 output"))
}

fn normalize_description(description: &str) -> String {
    description.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::{
        AssociatedPullRequest,
        CommitPullRequests,
        Database,
        ReleaseTag,
        changelog_entries_for_pull_requests_with,
        database_migration_updates_from_trees,
        previous_release_tag_from,
        protocol_update_from_lockfiles,
        pull_requests_for_commits_with,
        rust_msrv_update_from_manifests,
    };
    use crate::changelog::render;

    #[test]
    fn missing_pull_requests_are_rendered_as_changelog_issues() {
        let commits = vec![
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            "abcdef0123456789abcdef0123456789abcdef01".to_owned(),
        ];
        let changelog =
            pull_requests_for_commits_with("0xMiden/node", &commits, |_repo, commit| {
                Ok(if commit.starts_with('0') {
                    CommitPullRequests::Found(Vec::new())
                } else {
                    CommitPullRequests::CommitNotFound
                })
            })
            .unwrap();

        let notes = render::release_notes(
            "Release v1.2.3",
            None,
            None,
            &[],
            &[],
            &changelog.invalid_entries,
        );

        assert_eq!(
            notes,
            r"Release v1.2.3

## Changelog Entries Requiring Attention

- Missing PR for commit 0123456789ab: no associated pull request
- Missing PR for commit abcdef012345: commit was not found in GitHub repository 0xMiden/node

No release-note-worthy changes.
"
        );
    }

    #[test]
    fn associated_pull_requests_keep_first_commit_order_and_are_deduplicated() {
        let commits = vec!["first".to_owned(), "missing".to_owned(), "last".to_owned()];
        let pull_requests =
            pull_requests_for_commits_with("0xMiden/node", &commits, |_repo, commit| {
                Ok(CommitPullRequests::Found(match commit {
                    "first" => vec![42],
                    "missing" => Vec::new(),
                    "last" => vec![42, 43],
                    _ => unreachable!(),
                }))
            })
            .unwrap();

        let associations = pull_requests
            .pull_requests
            .iter()
            .map(|pull_request| (pull_request.number, pull_request.order))
            .collect::<Vec<_>>();

        assert_eq!(associations, vec![(42, 0), (43, 2)]);
        assert_eq!(pull_requests.invalid_entries.len(), 1);
        assert_eq!(pull_requests.invalid_entries[0].order, 1);
    }

    #[test]
    fn pull_request_lookup_failure_aborts_collection() {
        let commit = "0123456789abcdef0123456789abcdef01234567".to_owned();
        let result = pull_requests_for_commits_with(
            "0xMiden/node",
            std::slice::from_ref(&commit),
            |_repo, _commit| Err(anyhow!("authentication failed")),
        );

        let Err(err) = result else {
            panic!("expected pull request lookup to fail");
        };
        assert!(
            err.to_string()
                .contains("fetching pull requests associated with commit 0123456789abcdef")
        );
    }

    #[test]
    fn unavailable_pull_request_is_rendered_as_a_changelog_issue() {
        let pull_requests = [AssociatedPullRequest { number: 42, order: 0 }];
        let changelog = changelog_entries_for_pull_requests_with(
            "0xMiden/node",
            &pull_requests,
            |_repo, _pull_request| Err(anyhow!("pull request not found")),
        );

        let notes = render::release_notes(
            "Release v1.2.3",
            None,
            None,
            &[],
            &changelog.entries,
            &changelog.invalid_entries,
        );

        assert_eq!(
            notes,
            r"Release v1.2.3

## Changelog Entries Requiring Attention

- Broken PR #42: pull request body could not be fetched

No release-note-worthy changes.
"
        );
    }

    #[test]
    fn malformed_pull_request_is_rendered_as_a_changelog_issue() {
        let pull_requests = [
            AssociatedPullRequest { number: 42, order: 0 },
            AssociatedPullRequest { number: 43, order: 1 },
        ];
        let changelog = changelog_entries_for_pull_requests_with(
            "0xMiden/node",
            &pull_requests,
            |_repo, pull_request| {
                Ok(match pull_request {
                    42 => "## Summary\n\nNo changelog here.\n".to_owned(),
                    43 => "## Changelog\n\n```toml\n[[entry]\n```\n".to_owned(),
                    _ => unreachable!(),
                })
            },
        );

        let notes = render::release_notes(
            "Release v1.2.3",
            None,
            None,
            &[],
            &changelog.entries,
            &changelog.invalid_entries,
        );

        assert!(notes.contains("- Broken PR #42: missing `## Changelog` section"));
        assert!(notes.contains("- Broken PR #43: parsing changelog TOML block:"));
    }

    #[test]
    fn prerelease_uses_previous_prerelease() {
        let release = ReleaseTag::parse("v1.2.0-rc.1").unwrap();
        let tags = release_tags(&["v1.1.0", "v1.2.0-alpha.1", "v1.2.0-rc.0", "v1.2.0-rc.1"]);

        assert_eq!(previous_release_tag_from(&release, &tags), Some("v1.2.0-rc.0"));
    }

    #[test]
    fn first_prerelease_uses_previous_stable_release() {
        let release = ReleaseTag::parse("v1.2.0-rc.0").unwrap();
        let tags = release_tags(&["v1.0.0", "v1.1.0", "v1.2.0-rc.0"]);

        assert_eq!(previous_release_tag_from(&release, &tags), Some("v1.1.0"));
    }

    #[test]
    fn alpha_release_uses_previous_alpha_release() {
        let release = ReleaseTag::parse("v1.2.0-alpha.2").unwrap();
        let tags = release_tags(&["v1.1.0", "v1.2.0-alpha.1", "v1.2.0-alpha.2"]);

        assert_eq!(previous_release_tag_from(&release, &tags), Some("v1.2.0-alpha.1"));
    }

    #[test]
    fn stable_release_uses_previous_stable_release() {
        let release = ReleaseTag::parse("v1.2.0").unwrap();
        let tags = release_tags(&["v1.1.0", "v1.2.0-rc.0", "v1.2.0-rc.1", "v1.2.0"]);

        assert_eq!(previous_release_tag_from(&release, &tags), Some("v1.1.0"));
    }

    #[test]
    fn protocol_update_uses_the_versions_at_the_range_endpoints() {
        let previous = lockfile("0.16.0-rc.4");
        let current = lockfile("0.16.0-rc.9");

        let update = protocol_update_from_lockfiles(&previous, &current).unwrap().unwrap();

        assert_eq!(update.previous, semver::Version::parse("0.16.0-rc.4").unwrap());
        assert_eq!(update.current, semver::Version::parse("0.16.0-rc.9").unwrap());
    }

    #[test]
    fn unchanged_protocol_version_does_not_create_an_update() {
        let previous = lockfile("0.16.0-rc.9");
        let current = lockfile("0.16.0-rc.9");

        assert!(protocol_update_from_lockfiles(&previous, &current).unwrap().is_none());
    }

    #[test]
    fn rust_msrv_update_uses_the_versions_at_the_range_endpoints() {
        let previous = manifest("1.96.1");
        let current = manifest("1.98.0");

        let update = rust_msrv_update_from_manifests(&previous, &current).unwrap().unwrap();

        assert_eq!(update.previous, "1.96.1");
        assert_eq!(update.current, "1.98.0");
    }

    #[test]
    fn unchanged_rust_msrv_does_not_create_an_update() {
        let previous = manifest("1.98.0");
        let current = manifest("1.98.0");

        assert!(rust_msrv_update_from_manifests(&previous, &current).unwrap().is_none());
    }

    #[test]
    fn database_migration_updates_use_the_highest_prefix() {
        let previous = migration_tree(&[
            "crates/store/src/db/migrations/003_block_headers.sql",
            "bin/validator/src/db/migrations/001_initial.sql",
            "bin/ntx-builder/src/db/migrations/001_initial.sql",
        ]);
        let current = migration_tree(&[
            "crates/store/src/db/migrations/003_block_headers.sql",
            "crates/store/src/db/migrations/004_validity_intervals.sql",
            "crates/store/src/db/migrations/005_incremental_code_pruning.rs",
            "crates/store/src/db/migrations/005_incremental_code_pruning/support.rs",
            "crates/store/src/db/migrations/tests/mod.rs",
            "bin/validator/src/db/migrations/retired/001_initial.sql",
            "bin/ntx-builder/src/db/migrations/001_initial.sql",
            "bin/ntx-builder/src/db/migrations/003_sponsorship_notes.sql",
        ]);

        let updates = database_migration_updates_from_trees(&previous, &current);

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].database, Database::Store);
        assert_eq!((updates[0].previous, updates[0].current), (3, 5));
        assert_eq!(updates[1].database, Database::NtxBuilder);
        assert_eq!((updates[1].previous, updates[1].current), (1, 3));
    }

    #[test]
    fn unchanged_database_migration_prefix_does_not_create_an_update() {
        let previous = migration_tree(&["crates/store/src/db/migrations/005_active.sql"]);
        let current = migration_tree(&["crates/store/src/db/migrations/retired/005_active.sql"]);

        assert!(database_migration_updates_from_trees(&previous, &current).is_empty());
    }

    fn lockfile(protocol_version: &str) -> String {
        format!(
            r#"version = 4

[[package]]
name = "miden-protocol"
version = "{protocol_version}"
"#
        )
    }

    fn manifest(rust_msrv: &str) -> String {
        format!(
            r#"[workspace.package]
rust-version = "{rust_msrv}"
"#
        )
    }

    fn migration_tree(paths: &[&str]) -> String {
        paths.join("\n")
    }

    fn release_tags(tags: &[&str]) -> Vec<(String, semver::Version)> {
        tags.iter()
            .map(|tag| {
                let release = ReleaseTag::parse(tag).unwrap();
                ((*tag).to_owned(), release.version)
            })
            .collect()
    }
}
