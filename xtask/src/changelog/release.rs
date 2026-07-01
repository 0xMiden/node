use std::env;
use std::fmt;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use super::pr::{self, ChangelogDocument};
use super::{InvalidChangelogEntry, ReleaseNoteEntry};

pub(super) struct ChangelogEntries {
    pub(super) entries: Vec<ReleaseNoteEntry>,
    pub(super) invalid_entries: Vec<InvalidChangelogEntry>,
}

pub(super) struct CurrentChangelog {
    pub(super) title: String,
    pub(super) entries: Vec<ReleaseNoteEntry>,
    pub(super) invalid_entries: Vec<InvalidChangelogEntry>,
}

pub(super) fn release_changelog_entries(release_tag: &str) -> Result<ChangelogEntries> {
    ensure!(
        !release_tag.trim().is_empty(),
        "release tag must not be empty"
    );

    let release = ReleaseTag::parse(release_tag)?;
    let tag_commit = format!("refs/tags/{release_tag}^{{commit}}");
    let release_commit = git_output(&["rev-parse", "--verify", &tag_commit])
        .with_context(|| format!("resolving release tag {release_tag}"))?;
    let release_commit = release_commit.trim();

    ensure!(
        !release_commit.is_empty(),
        "release tag {release_tag} did not resolve to a commit"
    );

    let previous_stable_tag = previous_stable_tag(release.version, release_commit)?;
    let commits = commits_since_tag(&previous_stable_tag, &format!("refs/tags/{release_tag}"))?;
    ensure!(
        !commits.is_empty(),
        "release range refs/tags/{previous_stable_tag}..refs/tags/{release_tag} contains no commits"
    );
    let repo = github_repo()?;
    let pull_requests = pull_requests_for_commits(&repo, &commits, MissingPullRequest::Error)?;

    changelog_entries_for_pull_requests(&repo, &pull_requests)
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
            entries: Vec::new(),
            invalid_entries: Vec::new(),
        });
    }

    let repo = github_repo()?;
    let pull_requests =
        pull_requests_for_commits(&repo, &commits, MissingPullRequest::WarnAndSkip)?;
    let changelog = changelog_entries_for_pull_requests(&repo, &pull_requests)?;

    Ok(CurrentChangelog {
        title: format!("Changes since {previous_stable_tag}"),
        entries: changelog.entries,
        invalid_entries: changelog.invalid_entries,
    })
}

#[derive(Debug)]
struct ReleaseTag {
    version: StableVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Clone, Copy)]
enum MissingPullRequest {
    Error,
    WarnAndSkip,
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

        let (version, prerelease) = match version.split_once('-') {
            Some((version, prerelease)) => (version, Some(prerelease)),
            None => (version, None),
        };

        ensure!(
            prerelease.is_none_or(|prerelease| !prerelease.is_empty()),
            "release tags must look like v1.2.3 or v1.2.3-rc.1"
        );

        let Some(version) = StableVersion::parse(version) else {
            bail!("release tags must look like v1.2.3 or v1.2.3-rc.1");
        };

        Ok(Self { version })
    }
}

impl StableVersion {
    fn parse(source: &str) -> Option<Self> {
        let mut parts = source.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;

        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            major,
            minor,
            patch,
        })
    }

    fn parse_stable_tag(tag: &str) -> Option<Self> {
        let version = tag.strip_prefix('v')?;

        if version.contains('-') {
            return None;
        }

        Self::parse(version)
    }
}

impl fmt::Display for StableVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn previous_stable_tag(before: StableVersion, release_commit: &str) -> Result<String> {
    for (tag, version) in stable_tags_merged_into(release_commit)? {
        if version < before {
            return Ok(tag.to_owned());
        }
    }

    bail!("could not find a previous stable release tag before v{before}");
}

fn latest_stable_tag(release_commit: &str) -> Result<String> {
    stable_tags_merged_into(release_commit)?
        .into_iter()
        .map(|(tag, _version)| tag)
        .next()
        .context("could not find a stable release tag reachable from HEAD")
}

fn stable_tags_merged_into(commit: &str) -> Result<Vec<(String, StableVersion)>> {
    let tags = git_output(&[
        "tag",
        "--merged",
        commit,
        "--list",
        "v*",
        "--sort=-v:refname",
    ])
    .context("listing stable release tags")?;

    Ok(tags
        .lines()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .filter_map(|tag| {
            StableVersion::parse_stable_tag(tag).map(|version| (tag.to_owned(), version))
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

fn github_repo() -> Result<String> {
    if let Ok(repo) = env::var("GITHUB_REPOSITORY") {
        let repo = repo.trim();

        if !repo.is_empty() {
            return Ok(repo.to_owned());
        }
    }

    let mut command = Command::new("gh");
    command.args([
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ]);
    let repo = command_output(&mut command).context("resolving GitHub repository")?;
    let repo = repo.trim();

    ensure!(!repo.is_empty(), "could not resolve GitHub repository");

    Ok(repo.to_owned())
}

fn pull_requests_for_commits(
    repo: &str,
    commits: &[String],
    missing_pull_request: MissingPullRequest,
) -> Result<Vec<u64>> {
    let mut pull_requests = Vec::new();

    for commit in commits {
        let commit_pull_requests = pull_requests_for_commit(repo, commit)
            .with_context(|| format!("fetching pull requests associated with commit {commit}"))?;
        let CommitPullRequests::Found(commit_pull_requests) = commit_pull_requests else {
            match missing_pull_request {
                MissingPullRequest::Error => {
                    bail!("commit {commit} was not found in GitHub repository {repo}");
                }
                MissingPullRequest::WarnAndSkip => {
                    eprintln!(
                        "warning: skipping commit {commit}; not found in GitHub repository {repo}"
                    );
                    continue;
                }
            }
        };

        if commit_pull_requests.is_empty() {
            match missing_pull_request {
                MissingPullRequest::Error => {
                    bail!("commit {commit} has no associated pull request");
                }
                MissingPullRequest::WarnAndSkip => {
                    eprintln!("warning: skipping commit {commit}; no associated pull request");
                    continue;
                }
            }
        }

        for pull_request in commit_pull_requests {
            if !pull_requests.contains(&pull_request) {
                pull_requests.push(pull_request);
            }
        }
    }

    Ok(pull_requests)
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
    pull_requests: &[u64],
) -> Result<ChangelogEntries> {
    let mut entries = Vec::new();
    let mut invalid_entries = Vec::new();

    for (order, pull_request) in pull_requests.iter().enumerate() {
        let body = pull_request_body(repo, *pull_request)
            .with_context(|| format!("fetching pull request #{pull_request} body"))?;

        let document = match pr::changelog_document_from_pr_body(&body) {
            Ok(document) => document,
            Err(err) => {
                invalid_entries.push(InvalidChangelogEntry {
                    pr_number: *pull_request,
                    reason: normalize_description(&format!("{err:#}")),
                    order,
                });
                continue;
            }
        };

        let ChangelogDocument::Entries(pr_entries) = document else {
            continue;
        };

        for entry in pr_entries {
            entries.push(ReleaseNoteEntry {
                pr_number: *pull_request,
                scope: entry.scope,
                impact: entry.impact,
                description: normalize_description(&entry.description),
                order,
            });
        }
    }

    Ok(ChangelogEntries {
        entries,
        invalid_entries,
    })
}

fn pull_request_body(repo: &str, pull_request: u64) -> Result<String> {
    let pull_request = pull_request.to_string();
    let mut command = Command::new("gh");
    command.args([
        "pr",
        "view",
        &pull_request,
        "--repo",
        repo,
        "--json",
        "body",
        "--jq",
        ".body",
    ]);

    command_output(&mut command)
}

fn git_output(args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command.args(args);
    command_output(&mut command)
}

fn command_output(command: &mut Command) -> Result<String> {
    let command_display = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("running `{command_display}`"))?;

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
    let output = command
        .output()
        .with_context(|| format!("running `{command_display}`"))?;

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
