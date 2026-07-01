mod pr;
mod release;
mod render;
#[cfg(test)]
mod tests;

use anyhow::Result;
use serde::Deserialize;

pub fn verify_pr_body(source: &str) -> Result<()> {
    pr::verify_pr_body(source)
}

pub fn render_release_notes(release_tag: &str) -> Result<String> {
    let changelog = release::release_changelog_entries(release_tag)?;
    Ok(render::release_notes(
        &format!("Release {release_tag}"),
        &changelog.entries,
        &changelog.invalid_entries,
    ))
}

pub fn render_current_changelog() -> Result<String> {
    let changelog = release::current_changelog_entries()?;
    Ok(render::release_notes(
        &changelog.title,
        &changelog.entries,
        &changelog.invalid_entries,
    ))
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Scope {
    Rpc,
    Protocol,
    Docs,
    Node,
    NetworkMonitor,
    NtxBuilder,
    Prover,
    Validator,
    Internal,
    General,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Impact {
    Breaking,
    Migration,
    Added,
    Changed,
    Fixed,
    Removed,
    Deprecated,
}

#[derive(Debug)]
struct ReleaseNoteEntry {
    pr_number: u64,
    scope: Scope,
    impact: Impact,
    description: String,
    order: usize,
}

#[derive(Debug)]
struct InvalidChangelogEntry {
    pr_number: u64,
    reason: String,
    order: usize,
}
