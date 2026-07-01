use std::env;
use std::fmt;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use super::ReleaseNoteEntry;
use super::pr::{self, ChangelogDocument};

pub(super) fn release_note_entries(release_tag: &str) -> Result<Vec<ReleaseNoteEntry>> {
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
    let commits = release_commits(&previous_stable_tag, release_tag)?;
    let repo = github_repo()?;
    let pull_requests = pull_requests_for_commits(&repo, &commits)?;

    changelog_entries_for_pull_requests(&repo, &pull_requests)
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
    let tags = git_output(&[
        "tag",
        "--merged",
        release_commit,
        "--list",
        "v*",
        "--sort=-v:refname",
    ])
    .context("listing stable release tags")?;

    for tag in tags.lines().map(str::trim).filter(|tag| !tag.is_empty()) {
        let Some(version) = StableVersion::parse_stable_tag(tag) else {
            continue;
        };

        if version < before {
            return Ok(tag.to_owned());
        }
    }

    bail!("could not find a previous stable release tag before v{before}");
}

fn release_commits(previous_stable_tag: &str, release_tag: &str) -> Result<Vec<String>> {
    let range = format!("refs/tags/{previous_stable_tag}..refs/tags/{release_tag}");
    let commits = git_output(&["log", "--reverse", "--format=%H", &range])
        .with_context(|| format!("listing commits in {range}"))?;
    let commits = commits
        .lines()
        .map(str::trim)
        .filter(|commit| !commit.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    ensure!(
        !commits.is_empty(),
        "release range {range} contains no commits"
    );

    Ok(commits)
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

fn pull_requests_for_commits(repo: &str, commits: &[String]) -> Result<Vec<u64>> {
    let mut pull_requests = Vec::new();

    for commit in commits {
        let commit_pull_requests = pull_requests_for_commit(repo, commit)
            .with_context(|| format!("fetching pull requests associated with commit {commit}"))?;

        ensure!(
            !commit_pull_requests.is_empty(),
            "commit {commit} has no associated pull request"
        );

        for pull_request in commit_pull_requests {
            if !pull_requests.contains(&pull_request) {
                pull_requests.push(pull_request);
            }
        }
    }

    Ok(pull_requests)
}

fn pull_requests_for_commit(repo: &str, commit: &str) -> Result<Vec<u64>> {
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

    let output = command_output(&mut command)?;

    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<u64>()
                .with_context(|| format!("parsing pull request number `{line}`"))
        })
        .collect()
}

fn changelog_entries_for_pull_requests(
    repo: &str,
    pull_requests: &[u64],
) -> Result<Vec<ReleaseNoteEntry>> {
    let mut entries = Vec::new();

    for (order, pull_request) in pull_requests.iter().enumerate() {
        let body = pull_request_body(repo, *pull_request)
            .with_context(|| format!("fetching pull request #{pull_request} body"))?;

        let document = pr::changelog_document_from_pr_body(&body).with_context(|| {
            format!("parsing changelog metadata in pull request #{pull_request}")
        })?;

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

    Ok(entries)
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

fn normalize_description(description: &str) -> String {
    description.split_whitespace().collect::<Vec<_>>().join(" ")
}
