use std::fmt::Write as _;
use std::path::PathBuf;

use super::heuristics::Trigger;

const NO_CHANGELOG_LABEL: &str = "no changelog";

#[derive(Debug)]
pub(super) struct CheckResult {
    pub(super) pr: u64,
    pub(super) no_changelog_label: bool,
    pub(super) triggers: Vec<Trigger>,
    pub(super) changelog_files: Vec<PathBuf>,
    pub(super) validation_errors: Vec<String>,
}

impl CheckResult {
    pub(super) fn requires_changelog(&self) -> bool {
        !self.triggers.is_empty()
    }

    pub(super) fn has_changelog_change(&self) -> bool {
        !self.changelog_files.is_empty()
    }

    pub(super) fn render(&self) -> String {
        let mut output = String::new();
        writeln!(output, "## Changelog Check").expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");
        writeln!(output, "Pull request: #{pr}", pr = self.pr)
            .expect("writing to String cannot fail");
        writeln!(output).expect("writing to String cannot fail");

        self.render_status(&mut output);

        if self.triggers.is_empty() {
            writeln!(
                output,
                "\nNo likely changelog impact was detected by the current heuristics."
            )
            .expect("writing to String cannot fail");
        } else {
            writeln!(output, "\nLikely changelog impact detected:")
                .expect("writing to String cannot fail");
            for trigger in &self.triggers {
                writeln!(output, "- {trigger}").expect("writing to String cannot fail");
            }
        }

        if self.changelog_files.is_empty() {
            writeln!(output, "\nNo `changelog.d/**` changes were found.")
                .expect("writing to String cannot fail");
        } else {
            writeln!(output, "\nChangelog changes found:").expect("writing to String cannot fail");
            for path in &self.changelog_files {
                writeln!(output, "- `{}`", path.display()).expect("writing to String cannot fail");
            }
        }

        if !self.validation_errors.is_empty() {
            writeln!(output, "\nValidation errors:").expect("writing to String cannot fail");
            for error in &self.validation_errors {
                writeln!(output, "- {error}").expect("writing to String cannot fail");
            }
        }

        if self.requires_changelog() && !self.has_changelog_change() && !self.no_changelog_label {
            writeln!(
                output,
                "\nAdd or update any file under `changelog.d/**`, or apply `{NO_CHANGELOG_LABEL}` if this PR is intentionally not release-notable."
            )
            .expect("writing to String cannot fail");
        }

        output
    }

    fn status(&self) -> ReportStatus {
        if !self.validation_errors.is_empty()
            || (self.requires_changelog()
                && !self.has_changelog_change()
                && !self.no_changelog_label)
        {
            ReportStatus::Failed
        } else if self.requires_changelog()
            && !self.has_changelog_change()
            && self.no_changelog_label
        {
            ReportStatus::Overridden
        } else {
            ReportStatus::Passed
        }
    }

    fn render_status(&self, output: &mut String) {
        match self.status() {
            ReportStatus::Failed => {
                writeln!(output, "> [!CAUTION]").expect("writing to String cannot fail");
                if self.validation_errors.is_empty() {
                    writeln!(output, "> Changelog policy failed.")
                        .expect("writing to String cannot fail");
                } else {
                    writeln!(output, "> Changelog policy failed. Fix the validation errors below.")
                        .expect("writing to String cannot fail");
                }
            },
            ReportStatus::Overridden => {
                writeln!(output, "> [!WARNING]").expect("writing to String cannot fail");
                writeln!(
                    output,
                    "> Changelog impact was detected, but the `{NO_CHANGELOG_LABEL}` label is present."
                )
                .expect("writing to String cannot fail");
            },
            ReportStatus::Passed => {
                writeln!(output, "> [!NOTE]").expect("writing to String cannot fail");
                writeln!(output, "> Changelog policy passed.")
                    .expect("writing to String cannot fail");
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ReportStatus {
    Failed,
    Overridden,
    Passed,
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::super::heuristics::{Trigger, TriggerKind};
    use super::*;

    #[test]
    fn changelog_change_satisfies_required_entry_gate() {
        let result = CheckResult {
            pr: 1,
            no_changelog_label: false,
            triggers: vec![trigger(TriggerKind::Deployment, "docker-compose.yml")],
            changelog_files: vec![PathBuf::from("changelog.d/v0.15.0/1.toml")],
            validation_errors: Vec::new(),
        };

        assert!(result.requires_changelog());
        assert!(result.has_changelog_change());
        assert!(result.render().contains("> [!NOTE]\n> Changelog policy passed."));
    }

    #[test]
    fn missing_changelog_entry_renders_caution() {
        let result = CheckResult {
            pr: 1,
            no_changelog_label: false,
            triggers: vec![trigger(TriggerKind::Deployment, "docker-compose.yml")],
            changelog_files: Vec::new(),
            validation_errors: Vec::new(),
        };

        let report = result.render();

        assert!(report.contains("> [!CAUTION]\n> Changelog policy failed."));
        assert!(report.contains("Add or update any file under `changelog.d/**`"));
    }

    #[test]
    fn no_changelog_override_renders_warning() {
        let result = CheckResult {
            pr: 1,
            no_changelog_label: true,
            triggers: vec![trigger(TriggerKind::Deployment, "docker-compose.yml")],
            changelog_files: Vec::new(),
            validation_errors: Vec::new(),
        };

        assert!(result.render().contains(
            "> [!WARNING]\n> Changelog impact was detected, but the `no changelog` label is present."
        ));
    }

    #[test]
    fn validation_errors_render_caution() {
        let result = CheckResult {
            pr: 1,
            no_changelog_label: false,
            triggers: Vec::new(),
            changelog_files: vec![PathBuf::from("changelog.d/v0.15.0/1.toml")],
            validation_errors: vec![
                "`changelog.d/v0.15.0/1.toml`: summary must be a single line".to_owned(),
            ],
        };

        assert!(
            result.render().contains(
                "> [!CAUTION]\n> Changelog policy failed. Fix the validation errors below."
            )
        );
    }

    fn trigger(kind: TriggerKind, path: &str) -> Trigger {
        Trigger::new(kind, Path::new(path), Vec::new())
    }
}
