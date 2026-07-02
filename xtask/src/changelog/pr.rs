use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Deserialize;

use super::{Impact, Scope};

pub(super) fn verify_pr_body(source: &str) -> Result<()> {
    let _ = changelog_document_from_pr_body(source)?;
    Ok(())
}

pub(super) fn changelog_document_from_pr_body(source: &str) -> Result<ChangelogDocument> {
    let source = strip_html_comments(source);
    let section = changelog_section(&source)?;
    let toml_source = changelog_toml_block(&section)?;

    parse_document(&toml_source)
}

#[derive(Debug)]
pub(super) enum ChangelogDocument {
    Entries(Vec<Entry>),
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) scope: Scope,
    pub(super) impact: Impact,
    pub(super) description: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntriesDocument {
    entry: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoChangelogDocument {
    changelog: NoChangelog,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum NoChangelog {
    None,
}

fn strip_html_comments(source: &str) -> String {
    let mut stripped = String::with_capacity(source.len());
    let mut remaining = source;

    loop {
        let Some(start) = remaining.find("<!--") else {
            stripped.push_str(remaining);
            break;
        };

        stripped.push_str(&remaining[..start]);
        let comment = &remaining[start + "<!--".len()..];

        let Some(end) = comment.find("-->") else {
            preserve_newlines(&mut stripped, comment);
            break;
        };

        preserve_newlines(&mut stripped, &comment[..end]);
        remaining = &comment[end + "-->".len()..];
    }

    stripped
}

fn preserve_newlines(output: &mut String, source: &str) {
    for byte in source.bytes() {
        if byte == b'\n' {
            output.push('\n');
        }
    }
}

fn changelog_section(source: &str) -> Result<String> {
    let mut found = false;
    let mut in_fence = false;
    let mut section = String::new();

    for line in source.lines() {
        let trimmed = line.trim_start();

        if !in_fence && let Some((level, title)) = markdown_heading(line) {
            if level == 2 && title.eq_ignore_ascii_case("changelog") {
                found = true;
                continue;
            }

            if found && level <= 2 {
                break;
            }
        }

        if found {
            section.push_str(line);
            section.push('\n');
        }

        if trimmed.starts_with("```") {
            in_fence = !in_fence;
        }
    }

    ensure!(found, "missing `## Changelog` section");
    Ok(section)
}

fn markdown_heading(line: &str) -> Option<(usize, &str)> {
    let line = line.trim_start();
    let level = line.bytes().take_while(|byte| *byte == b'#').count();

    if level == 0 {
        return None;
    }

    let rest = &line[level..];
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }

    let title = rest.trim().trim_end_matches('#').trim();
    Some((level, title))
}

fn changelog_toml_block(section: &str) -> Result<String> {
    let mut current_block = String::new();
    let mut in_fence = false;
    let mut capture_toml = false;

    for line in section.lines() {
        let trimmed = line.trim_start();

        if in_fence {
            if trimmed.starts_with("```") {
                if capture_toml {
                    return Ok(current_block);
                }

                in_fence = false;
                capture_toml = false;
                continue;
            }

            if capture_toml {
                current_block.push_str(line);
                current_block.push('\n');
            }

            continue;
        }

        let Some(info) = trimmed.strip_prefix("```") else {
            continue;
        };

        in_fence = true;
        let language = info.split_whitespace().next().unwrap_or_default();
        capture_toml = language.eq_ignore_ascii_case("toml");
    }

    if capture_toml {
        bail!("unterminated fenced `toml` block in `## Changelog` section");
    }

    bail!("missing fenced `toml` block in `## Changelog` section");
}

fn parse_document(source: &str) -> Result<ChangelogDocument> {
    let document = toml::from_str::<toml::Table>(source).context("parsing changelog TOML block")?;

    let has_entries = document.contains_key("entry");
    let has_no_changelog_marker = document.contains_key("changelog");

    match (has_entries, has_no_changelog_marker) {
        (true, true) => {
            bail!("changelog TOML block cannot contain both `[[entry]]` and `changelog`")
        },
        (true, false) => Ok(ChangelogDocument::Entries(parse_entries(source)?)),
        (false, true) => {
            validate_no_changelog(source)?;
            Ok(ChangelogDocument::None)
        },
        (false, false) => {
            bail!("changelog TOML block must contain `[[entry]]` or `changelog = \"none\"`")
        },
    }
}

fn parse_entries(source: &str) -> Result<Vec<Entry>> {
    let document = toml::from_str::<EntriesDocument>(source)
        .map_err(|err| anyhow!("parsing changelog entries: {err}"))?;

    ensure!(!document.entry.is_empty(), "`[[entry]]` must contain at least one entry");

    for (index, entry) in document.entry.iter().enumerate() {
        validate_entry(index, entry)?;
    }

    Ok(document.entry)
}

fn validate_entry(index: usize, entry: &Entry) -> Result<()> {
    let ordinal = index + 1;

    let _ = entry.scope;
    let _ = entry.impact;

    ensure!(
        !entry.description.trim().is_empty(),
        "entry {ordinal} field `description` must not be empty"
    );

    Ok(())
}

fn validate_no_changelog(source: &str) -> Result<()> {
    let document = toml::from_str::<NoChangelogDocument>(source)
        .map_err(|err| anyhow!("parsing no-changelog marker: {err}"))?;

    let _ = document.changelog;
    ensure!(
        !document.reason.trim().is_empty(),
        "`reason` must not be empty when `changelog = \"none\"`"
    );

    Ok(())
}
