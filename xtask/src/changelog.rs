use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Deserialize;

pub fn verify_pr_body(source: &str) -> Result<()> {
    let source = strip_html_comments(source);
    let section = changelog_section(&source)?;
    let toml_source = changelog_toml_block(&section)?;

    validate_document(&toml_source)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntriesDocument {
    entry: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    scope: Scope,
    impact: Impact,
    description: String,
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
    General,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Impact {
    Breaking,
    Added,
    Changed,
    Fixed,
    Removed,
    Deprecated,
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

fn validate_document(source: &str) -> Result<()> {
    let document = toml::from_str::<toml::Table>(source).context("parsing changelog TOML block")?;

    let has_entries = document.contains_key("entry");
    let has_no_changelog_marker = document.contains_key("changelog");

    match (has_entries, has_no_changelog_marker) {
        (true, true) => {
            bail!("changelog TOML block cannot contain both `[[entry]]` and `changelog`")
        },
        (true, false) => validate_entries(source),
        (false, true) => validate_no_changelog(source),
        (false, false) => {
            bail!("changelog TOML block must contain `[[entry]]` or `changelog = \"none\"`")
        },
    }
}

fn validate_entries(source: &str) -> Result<()> {
    let document = toml::from_str::<EntriesDocument>(source)
        .map_err(|err| anyhow!("parsing changelog entries: {err}"))?;

    ensure!(!document.entry.is_empty(), "`[[entry]]` must contain at least one entry");

    for (index, entry) in document.entry.iter().enumerate() {
        validate_entry(index, entry)?;
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_body(toml: &str) -> String {
        format!(
            r"## Summary

Changes something.

## Changelog

```toml
{toml}
```
"
        )
    }

    #[test]
    fn accepts_single_entry() {
        let body = valid_body(
            r#"[[entry]]
scope       = "rpc"
impact      = "breaking"
description = "Changed `GetBlockByNumber` to accept a `BlockRequest`."
"#,
        );

        verify_pr_body(&body).unwrap();
    }

    #[test]
    fn accepts_multiple_entries() {
        let body = valid_body(
            r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = "Changed the RPC response shape."

[[entry]]
scope       = "node"
impact      = "added"
description = "Added a bootstrap command."
"#,
        );

        verify_pr_body(&body).unwrap();
    }

    #[test]
    fn accepts_no_changelog_marker() {
        let body = valid_body(
            r#"changelog = "none"
reason    = "Internal refactor only."
"#,
        );

        verify_pr_body(&body).unwrap();
    }

    #[test]
    fn ignores_toml_examples_in_html_comments() {
        let body = r#"## Summary

## Changelog

<!--
```toml
changelog = "none"
reason    = "Example only."
```
-->

```toml
[[entry]]
scope       = "docs"
impact      = "fixed"
description = "Fixed the operator migration instructions."
```
"#;

        verify_pr_body(body).unwrap();
    }

    #[test]
    fn accepts_examples_after_changelog_entry() {
        let body = r#"This PR tries out another new changelog system.

## Changelog

```toml
[[entry]]
scope       = "general"
impact      = "added"
description = "changelog is now derived from PR bodies"

# Supports multiple.
# [[entry]]
# scope       = "general"
# impact      = "added"
# description = "changelog is now derived from PR bodies again"
```

or opt out:

```toml
#changelog = "none"
#reason    = "Internal change only."
```

This later code fence is intentionally incomplete and should not affect the
already-parsed changelog block.

```text
"#;

        verify_pr_body(body).unwrap();
    }

    #[test]
    fn rejects_missing_changelog_section() {
        let err = verify_pr_body("## Summary\n\nNo changelog here.\n").unwrap_err();

        assert!(err.to_string().contains("missing `## Changelog` section"));
    }

    #[test]
    fn rejects_missing_toml_block() {
        let err = verify_pr_body("## Changelog\n\nNo block.\n").unwrap_err();

        assert!(err.to_string().contains("missing fenced `toml` block"));
    }

    #[test]
    fn rejects_empty_template_values() {
        let body = valid_body(
            r#"[[entry]]
scope       = ""
impact      = ""
description = ""
"#,
        );

        let err = verify_pr_body(&body).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn rejects_empty_description() {
        let body = valid_body(
            r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = ""
"#,
        );

        let err = verify_pr_body(&body).unwrap_err();

        assert!(err.to_string().contains("entry 1 field `description` must not be empty"));
    }

    #[test]
    fn rejects_unknown_enum_value() {
        let body = valid_body(
            r#"[[entry]]
scope       = "rpc"
impact      = "improved"
description = "Improved RPC behavior."
"#,
        );

        let err = verify_pr_body(&body).unwrap_err();

        assert!(err.to_string().contains("unknown variant `improved`"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let body = valid_body(
            r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = "Changed RPC behavior."
component   = "rpc"
"#,
        );

        let err = verify_pr_body(&body).unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }
}
