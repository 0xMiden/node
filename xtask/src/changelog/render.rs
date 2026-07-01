use std::fmt::Write as _;

use super::{Impact, ReleaseNoteEntry, Scope};

pub(super) fn release_notes(release_tag: &str, entries: &[ReleaseNoteEntry]) -> String {
    let mut notes = format!("Release {release_tag}\n");

    if entries.is_empty() {
        notes.push_str("\nNo release-note-worthy changes.\n");
        return notes;
    }

    append_impact_section(&mut notes, "Breaking Changes", Impact::Breaking, entries);
    append_impact_section(&mut notes, "Migrations", Impact::Migration, entries);

    notes.push_str("\n## Changes by Scope\n");

    for scope in SCOPE_ORDER {
        let mut entries = entries
            .iter()
            .filter(|entry| entry.scope == scope)
            .collect::<Vec<_>>();

        if entries.is_empty() {
            continue;
        }

        entries.sort_by_key(|entry| (entry.impact.sort_key(), entry.order));

        writeln!(notes, "\n### {scope}\n").expect("writing to String cannot fail");

        for entry in entries {
            append_scope_entry(&mut notes, entry);
        }
    }

    notes
}

fn append_impact_section(
    notes: &mut String,
    title: &str,
    impact: Impact,
    entries: &[ReleaseNoteEntry],
) {
    let mut entries = entries
        .iter()
        .filter(|entry| entry.impact == impact)
        .collect::<Vec<_>>();

    if entries.is_empty() {
        return;
    }

    entries.sort_by_key(|entry| entry.order);

    writeln!(notes, "\n## {title}\n").expect("writing to String cannot fail");

    for entry in entries {
        append_callout_entry(notes, entry);
    }
}

fn append_scope_entry(notes: &mut String, entry: &ReleaseNoteEntry) {
    let impact = entry.impact;
    let description = &entry.description;
    let pr_number = entry.pr_number;

    writeln!(notes, "- **{impact}:** {description} (#{pr_number})")
        .expect("writing to String cannot fail");
}

fn append_callout_entry(notes: &mut String, entry: &ReleaseNoteEntry) {
    let scope = entry.scope;
    let description = &entry.description;
    let pr_number = entry.pr_number;

    writeln!(notes, "- **{scope}:** {description} (#{pr_number})")
        .expect("writing to String cannot fail");
}

impl Scope {
    const fn sort_order() -> [Self; 10] {
        [
            Self::General,
            Self::Protocol,
            Self::Rpc,
            Self::Node,
            Self::Prover,
            Self::NtxBuilder,
            Self::Validator,
            Self::NetworkMonitor,
            Self::Docs,
            Self::Internal,
        ]
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::General => "General",
            Self::Protocol => "Protocol",
            Self::Rpc => "RPC",
            Self::Node => "Node",
            Self::Prover => "Prover",
            Self::NtxBuilder => "NTX Builder",
            Self::Validator => "Validator",
            Self::NetworkMonitor => "Network Monitor",
            Self::Docs => "Docs",
            Self::Internal => "Internal",
        };

        formatter.write_str(label)
    }
}

impl Impact {
    fn sort_key(self) -> usize {
        match self {
            Self::Breaking => 0,
            Self::Migration => 1,
            Self::Added => 2,
            Self::Changed => 3,
            Self::Fixed => 4,
            Self::Deprecated => 5,
            Self::Removed => 6,
        }
    }
}

impl std::fmt::Display for Impact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Breaking => "Breaking",
            Self::Migration => "Migration",
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Fixed => "Fixed",
            Self::Deprecated => "Deprecated",
            Self::Removed => "Removed",
        };

        formatter.write_str(label)
    }
}

const SCOPE_ORDER: [Scope; 10] = Scope::sort_order();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_callouts_and_changes_by_scope() {
        let entries = vec![
            ReleaseNoteEntry {
                pr_number: 10,
                scope: Scope::Rpc,
                impact: Impact::Breaking,
                description: "Changed request shape.".to_owned(),
                order: 0,
            },
            ReleaseNoteEntry {
                pr_number: 11,
                scope: Scope::Protocol,
                impact: Impact::Migration,
                description: "Added database migration.".to_owned(),
                order: 1,
            },
            ReleaseNoteEntry {
                pr_number: 12,
                scope: Scope::Node,
                impact: Impact::Added,
                description: "Added startup command.".to_owned(),
                order: 2,
            },
            ReleaseNoteEntry {
                pr_number: 13,
                scope: Scope::General,
                impact: Impact::Fixed,
                description: "Fixed release metadata.".to_owned(),
                order: 3,
            },
        ];

        let notes = release_notes("v0.16.0", &entries);

        assert_eq!(
            notes,
            r#"Release v0.16.0

## Breaking Changes

- **RPC:** Changed request shape. (#10)

## Migrations

- **Protocol:** Added database migration. (#11)

## Changes by Scope

### General

- **Fixed:** Fixed release metadata. (#13)

### Protocol

- **Migration:** Added database migration. (#11)

### RPC

- **Breaking:** Changed request shape. (#10)

### Node

- **Added:** Added startup command. (#12)
"#
        );
    }
}
