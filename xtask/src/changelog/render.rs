use std::fmt::{self, Write as _};
use std::path::Path;

use anyhow::{Context, Result};

use super::entry::{Category, Component, Entry};

const REPOSITORY_PULL_URL: &str = "https://github.com/0xMiden/node/pull";
const CHANGELOG_HEADING: &str = "# Changelog";
const ARCHIVED_CHANGELOG_NOTICE: &str =
    "Historical changelog entries are archived in [CHANGELOG.archived.md](CHANGELOG.archived.md).";

pub(super) fn render_section(version: &str, date: &str, entries: &[Entry]) -> String {
    let mut output = String::new();
    writeln!(output, "## {version} ({date})").expect("writing to String cannot fail");

    for component in Component::ALL {
        let component_entries =
            entries.iter().filter(|entry| entry.component == component).collect::<Vec<_>>();

        if component_entries.is_empty() {
            continue;
        }

        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "### {component}").expect("writing to String cannot fail");

        let breaking = component_entries
            .iter()
            .copied()
            .filter(|entry| entry.breaking)
            .collect::<Vec<_>>();
        if !breaking.is_empty() {
            render_entries("Breaking", &breaking, &mut output);
        }

        for category in Category::ALL {
            let category_entries = component_entries
                .iter()
                .copied()
                .filter(|entry| !entry.breaking && entry.category == category)
                .collect::<Vec<_>>();

            if !category_entries.is_empty() {
                render_entries(category, &category_entries, &mut output);
            }
        }
    }

    output
}

pub(super) fn write_changelog(path: &Path, section: &str) -> Result<()> {
    fs_err::write(path, render_changelog(section))
        .with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

fn render_changelog(section: &str) -> String {
    format!("{CHANGELOG_HEADING}\n\n{ARCHIVED_CHANGELOG_NOTICE}\n\n{}\n", section.trim_end())
}

fn render_entries(title: impl fmt::Display, entries: &[&Entry], output: &mut String) {
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "#### {title}").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");

    for entry in entries {
        writeln!(output, "- {} ({})", entry.summary, pr_links(entry))
            .expect("writing to String cannot fail");
    }
}

fn pr_links(entry: &Entry) -> String {
    std::iter::once(entry.pr)
        .chain(entry.related_prs.iter().copied())
        .map(|pr| format!("[#{pr}]({REPOSITORY_PULL_URL}/{pr})"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn renders_breaking_entries_before_category_entries() {
        let entries = vec![
            Entry {
                source: PathBuf::from("changelog.d/v0.15.0/2.toml"),
                pr: 2,
                related_prs: Vec::new(),
                component: Component::RpcApi,
                category: Category::Fixed,
                breaking: false,
                summary: "Fixed response metadata.".to_owned(),
            },
            Entry {
                source: PathBuf::from("changelog.d/v0.15.0/1.toml"),
                pr: 1,
                related_prs: Vec::new(),
                component: Component::RpcApi,
                category: Category::Changed,
                breaking: true,
                summary: "Changed request shape.".to_owned(),
            },
        ];

        let section = render_section("v0.15.0", "Unreleased", &entries);

        assert!(section.contains("### RPC API"));
        assert!(section.contains("#### Breaking"));
        assert!(section.contains("#### Fixed"));
        assert!(
            section.find("#### Breaking").unwrap() < section.find("#### Fixed").unwrap(),
            "breaking entries should render before fixed entries:\n{section}"
        );
    }

    #[test]
    fn renders_related_pr_links_on_same_entry() {
        let entries = vec![Entry {
            source: PathBuf::from("changelog.d/v0.15.0/2149.toml"),
            pr: 2149,
            related_prs: vec![2150, 2151],
            component: Component::NtxBuilder,
            category: Category::Added,
            breaking: false,
            summary: "Added builder bootstrap support.".to_owned(),
        }];

        let section = render_section("v0.15.0", "Unreleased", &entries);

        assert!(section.contains(
            "Added builder bootstrap support. ([#2149](https://github.com/0xMiden/node/pull/2149), [#2150](https://github.com/0xMiden/node/pull/2150), [#2151](https://github.com/0xMiden/node/pull/2151))"
        ));
    }

    #[test]
    fn release_renders_full_changelog() {
        let section = "## v0.15.0 (2026-06-03)\n\n- New.";

        assert_eq!(
            render_changelog(section),
            "# Changelog\n\nHistorical changelog entries are archived in [CHANGELOG.archived.md](CHANGELOG.archived.md).\n\n## v0.15.0 (2026-06-03)\n\n- New.\n"
        );
    }
}
