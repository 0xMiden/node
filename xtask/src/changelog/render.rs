use std::fmt::{self, Write as _};
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::entry::{Category, Component, Entry};

const REPOSITORY_PULL_URL: &str = "https://github.com/0xMiden/node/pull";

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

pub(super) fn prepend_to_changelog(path: &Path, version: &str, section: &str) -> Result<()> {
    let source =
        fs_err::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        !source.contains(&format!("## {version} (")),
        "{} already contains a section for {version}",
        path.display()
    );

    let heading = "# Changelog";
    ensure!(source.starts_with(heading), "{} must start with {heading:?}", path.display());

    let rest = source.strip_prefix(heading).expect("source starts with heading");
    let rest = rest.trim_start_matches('\n');
    let updated = format!("{heading}\n\n{}\n\n{}", section.trim_end(), rest);

    fs_err::write(path, updated).with_context(|| format!("writing {}", path.display()))?;

    Ok(())
}

fn render_entries(title: impl fmt::Display, entries: &[&Entry], output: &mut String) {
    writeln!(output).expect("writing to String cannot fail");
    writeln!(output, "#### {title}").expect("writing to String cannot fail");
    writeln!(output).expect("writing to String cannot fail");

    for entry in entries {
        writeln!(
            output,
            "- {} ([#{}]({}/{}))",
            entry.summary, entry.pr, REPOSITORY_PULL_URL, entry.pr
        )
        .expect("writing to String cannot fail");
    }
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
                component: Component::RpcApi,
                category: Category::Fixed,
                breaking: false,
                summary: "Fixed response metadata.".to_owned(),
            },
            Entry {
                source: PathBuf::from("changelog.d/v0.15.0/1.toml"),
                pr: 1,
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
    fn release_prepends_after_changelog_heading() {
        let source = "# Changelog\n\n## v0.14.0 (2026-04-01)\n\n- Existing.\n";
        let heading = "# Changelog";
        let rest = source.strip_prefix(heading).unwrap().trim_start_matches('\n');
        let section = "## v0.15.0 (2026-06-03)\n\n- New.";
        let updated = format!("{heading}\n\n{}\n\n{}", section.trim_end(), rest);

        assert_eq!(
            updated,
            "# Changelog\n\n## v0.15.0 (2026-06-03)\n\n- New.\n\n## v0.14.0 (2026-04-01)\n\n- Existing.\n"
        );
    }
}
