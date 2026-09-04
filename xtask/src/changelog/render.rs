use std::fmt::Write as _;

use super::{
    Database,
    DatabaseMigrationUpdate,
    Impact,
    InvalidChangelogEntry,
    InvalidChangelogSource,
    ProtocolUpdate,
    ReleaseNoteEntry,
    RustMsrvUpdate,
    Scope,
};

pub(super) fn release_notes(
    title: &str,
    protocol_update: Option<&ProtocolUpdate>,
    rust_msrv_update: Option<&RustMsrvUpdate>,
    database_migration_updates: &[DatabaseMigrationUpdate],
    entries: &[ReleaseNoteEntry],
    invalid_entries: &[InvalidChangelogEntry],
) -> String {
    let mut notes = format!("{title}\n");

    if protocol_update.is_some()
        || rust_msrv_update.is_some()
        || !database_migration_updates.is_empty()
    {
        notes.push('\n');
    }

    if let Some(update) = protocol_update {
        append_protocol_update(&mut notes, update);
    }

    if let Some(update) = rust_msrv_update {
        append_rust_msrv_update(&mut notes, update);
    }

    append_database_migration_updates(&mut notes, database_migration_updates);

    append_invalid_entries(&mut notes, invalid_entries);

    if entries.is_empty() {
        if protocol_update.is_none()
            && rust_msrv_update.is_none()
            && database_migration_updates.is_empty()
        {
            notes.push_str("\nNo release-note-worthy changes.\n");
        }
        return notes;
    }

    append_impact_section(&mut notes, "Breaking Changes", Impact::Breaking, entries);

    notes.push_str("\n## Changes by Scope\n");

    for scope in SCOPE_ORDER {
        append_scope_section(&mut notes, scope, entries);
    }

    notes
}

fn append_scope_section(notes: &mut String, scope: Scope, entries: &[ReleaseNoteEntry]) {
    let mut entries = entries.iter().filter(|entry| entry.scope == scope).collect::<Vec<_>>();

    if entries.is_empty() {
        return;
    }

    entries.sort_by_key(|entry| (entry.impact.sort_key(), entry.order));

    writeln!(notes, "\n### {scope}\n").expect("writing to String cannot fail");

    for entry in entries {
        append_scope_entry(notes, entry);
    }
}

fn append_protocol_update(notes: &mut String, update: &ProtocolUpdate) {
    let previous = &update.previous;
    let current = &update.current;

    writeln!(notes, "Protocol support updated from `{previous}` to `{current}`.")
        .expect("writing to String cannot fail");
}

fn append_rust_msrv_update(notes: &mut String, update: &RustMsrvUpdate) {
    let previous = &update.previous;
    let current = &update.current;

    writeln!(notes, "Rust MSRV updated from `{previous}` to `{current}`.")
        .expect("writing to String cannot fail");
}

fn append_database_migration_updates(notes: &mut String, updates: &[DatabaseMigrationUpdate]) {
    for update in updates {
        let database = update.database;
        let previous = update.previous;
        let current = update.current;

        writeln!(
            notes,
            "{database} database schema migrated from `{previous:03}` to `{current:03}`."
        )
        .expect("writing to String cannot fail");
    }
}

fn append_invalid_entries(notes: &mut String, invalid_entries: &[InvalidChangelogEntry]) {
    if invalid_entries.is_empty() {
        return;
    }

    let mut invalid_entries = invalid_entries.iter().collect::<Vec<_>>();
    invalid_entries.sort_by_key(|entry| entry.order);

    writeln!(notes, "\n## Changelog Entries Requiring Attention\n")
        .expect("writing to String cannot fail");

    for entry in invalid_entries {
        let reason = &entry.reason;

        match &entry.source {
            InvalidChangelogSource::PullRequest(pr_number) => {
                writeln!(notes, "- Broken PR #{pr_number}: {reason}")
                    .expect("writing to String cannot fail");
            },
            InvalidChangelogSource::Commit(commit) => {
                let abbreviated_commit = commit.chars().take(12).collect::<String>();
                writeln!(notes, "- Missing PR for commit {abbreviated_commit}: {reason}")
                    .expect("writing to String cannot fail");
            },
        }
    }
}

fn append_impact_section(
    notes: &mut String,
    title: &str,
    impact: Impact,
    entries: &[ReleaseNoteEntry],
) {
    let mut entries = entries.iter().filter(|entry| entry.impact == impact).collect::<Vec<_>>();

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
            Self::Rpc,
            Self::Node,
            Self::Prover,
            Self::NtxBuilder,
            Self::Validator,
            Self::NoteTransport,
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
            Self::Rpc => "RPC",
            Self::Node => "Node",
            Self::Prover => "Prover",
            Self::NtxBuilder => "NTX Builder",
            Self::Validator => "Validator",
            Self::NoteTransport => "Note Transport",
            Self::NetworkMonitor => "Network Monitor",
            Self::Docs => "Docs",
            Self::Internal => "Internal",
        };

        formatter.write_str(label)
    }
}

impl std::fmt::Display for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Store => "Store",
            Self::Validator => "Validator",
            Self::NtxBuilder => "NTX Builder",
        };

        formatter.write_str(label)
    }
}

impl Impact {
    fn sort_key(self) -> usize {
        match self {
            Self::Breaking => 0,
            Self::Added => 1,
            Self::Changed => 2,
            Self::Fixed => 3,
            Self::Deprecated => 4,
            Self::Removed => 5,
        }
    }
}

impl std::fmt::Display for Impact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Breaking => "Breaking",
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
        let invalid_entries = vec![InvalidChangelogEntry {
            source: InvalidChangelogSource::PullRequest(9),
            reason: "missing `## Changelog` section".to_owned(),
            order: 0,
        }];
        let entries = vec![
            ReleaseNoteEntry {
                pr_number: 10,
                scope: Scope::Rpc,
                impact: Impact::Breaking,
                description: "Changed request shape.".to_owned(),
                order: 0,
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
        let protocol_update = ProtocolUpdate {
            previous: semver::Version::parse("0.16.0-rc.4").unwrap(),
            current: semver::Version::parse("0.16.0-rc.9").unwrap(),
        };
        let rust_msrv_update = RustMsrvUpdate {
            previous: "1.96.1".to_owned(),
            current: "1.98.0".to_owned(),
        };
        let database_migration_updates = vec![
            DatabaseMigrationUpdate {
                database: Database::Store,
                previous: 3,
                current: 5,
            },
            DatabaseMigrationUpdate {
                database: Database::NtxBuilder,
                previous: 1,
                current: 3,
            },
        ];

        let notes = release_notes(
            "Release v0.16.0",
            Some(&protocol_update),
            Some(&rust_msrv_update),
            &database_migration_updates,
            &entries,
            &invalid_entries,
        );

        assert_eq!(
            notes,
            r"Release v0.16.0

Protocol support updated from `0.16.0-rc.4` to `0.16.0-rc.9`.
Rust MSRV updated from `1.96.1` to `1.98.0`.
Store database schema migrated from `003` to `005`.
NTX Builder database schema migrated from `001` to `003`.

## Changelog Entries Requiring Attention

- Broken PR #9: missing `## Changelog` section

## Breaking Changes

- **RPC:** Changed request shape. (#10)

## Changes by Scope

### General

- **Fixed:** Fixed release metadata. (#13)

### RPC

- **Breaking:** Changed request shape. (#10)

### Node

- **Added:** Added startup command. (#12)
"
        );
    }

    #[test]
    fn renders_a_protocol_update_without_pr_entries() {
        let protocol_update = ProtocolUpdate {
            previous: semver::Version::parse("0.16.0-rc.4").unwrap(),
            current: semver::Version::parse("0.16.0-rc.9").unwrap(),
        };

        let notes = release_notes("Release v0.16.0", Some(&protocol_update), None, &[], &[], &[]);

        assert_eq!(
            notes,
            r"Release v0.16.0

Protocol support updated from `0.16.0-rc.4` to `0.16.0-rc.9`.
"
        );
    }

    #[test]
    fn renders_a_rust_msrv_update_without_pr_entries() {
        let rust_msrv_update = RustMsrvUpdate {
            previous: "1.96.1".to_owned(),
            current: "1.98.0".to_owned(),
        };

        let notes = release_notes("Release v0.16.0", None, Some(&rust_msrv_update), &[], &[], &[]);

        assert_eq!(
            notes,
            r"Release v0.16.0

Rust MSRV updated from `1.96.1` to `1.98.0`.
"
        );
    }

    #[test]
    fn renders_database_migration_updates_without_pr_entries() {
        let updates = vec![DatabaseMigrationUpdate {
            database: Database::Store,
            previous: 3,
            current: 5,
        }];

        let notes = release_notes("Release v0.16.0", None, None, &updates, &[], &[]);

        assert_eq!(
            notes,
            r"Release v0.16.0

Store database schema migrated from `003` to `005`.
"
        );
    }
}
