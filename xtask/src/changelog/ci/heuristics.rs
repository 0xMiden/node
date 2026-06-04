use std::fmt;
use std::path::{Path, PathBuf};

const MIDEN_PROTOCOL_DEPENDENCIES: &[&str] = &[
    "miden-agglayer",
    "miden-block-prover",
    "miden-protocol",
    "miden-standards",
    "miden-testing",
    "miden-tx",
    "miden-tx-batch-prover",
    "miden-crypto",
];

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct Trigger {
    pub(super) kind: TriggerKind,
    pub(super) path: PathBuf,
    pub(super) details: Vec<&'static str>,
}

impl Trigger {
    pub(super) fn new(kind: TriggerKind, path: &Path, details: Vec<&'static str>) -> Self {
        Self { kind, path: path.to_path_buf(), details }
    }
}

impl fmt::Display for Trigger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: `{}`", self.kind, self.path.display())?;

        if !self.details.is_empty() {
            write!(formatter, " ({})", self.details.join(", "))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum TriggerKind {
    Cli,
    MidenProtocolDependency,
    Protobuf,
    Deployment,
    OperatorDocs,
    DatabaseConfig,
}

impl fmt::Display for TriggerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cli => "CLI surface",
            Self::MidenProtocolDependency => "Miden protocol dependency",
            Self::Protobuf => "Protobuf surface",
            Self::Deployment => "Deployment surface",
            Self::OperatorDocs => "Operator docs",
            Self::DatabaseConfig => "Database/config compatibility",
        })
    }
}

pub(super) fn classify_path(
    path: &Path,
    file_text: Option<&str>,
    diff_text: Option<&str>,
) -> Vec<Trigger> {
    let mut triggers = Vec::new();

    if is_cli_change(path, file_text) {
        triggers.push(Trigger::new(TriggerKind::Cli, path, Vec::new()));
    }

    let miden_dependencies = changed_miden_protocol_dependencies(path, diff_text);
    if !miden_dependencies.is_empty() {
        triggers.push(Trigger::new(TriggerKind::MidenProtocolDependency, path, miden_dependencies));
    }

    if has_prefix(path, "proto/proto") {
        triggers.push(Trigger::new(TriggerKind::Protobuf, path, Vec::new()));
    }

    if is_deployment_change(path) {
        triggers.push(Trigger::new(TriggerKind::Deployment, path, Vec::new()));
    }

    if is_operator_docs_change(path) {
        triggers.push(Trigger::new(TriggerKind::OperatorDocs, path, Vec::new()));
    }

    if is_database_config_change(path) {
        triggers.push(Trigger::new(TriggerKind::DatabaseConfig, path, Vec::new()));
    }

    triggers
}

pub(super) fn needs_dependency_diff(path: &Path) -> bool {
    path == Path::new("Cargo.toml") || path == Path::new("Cargo.lock")
}

fn is_cli_change(path: &Path, file_text: Option<&str>) -> bool {
    if !has_prefix(path, "bin")
        || path.extension().and_then(|extension| extension.to_str()) != Some("rs")
    {
        return false;
    }

    let path = path_string(path);
    path.ends_with("/src/main.rs")
        || path.contains("/src/commands/")
        || path.contains("/src/cli/")
        || file_text.is_some_and(looks_like_clap_file)
}

fn looks_like_clap_file(file_text: &str) -> bool {
    file_text.contains("use clap")
        || file_text.contains("clap::")
        || file_text.contains("derive(Parser")
        || file_text.contains("derive(Subcommand")
        || file_text.contains("derive(Args")
        || file_text.contains("derive(ValueEnum")
}

fn changed_miden_protocol_dependencies(path: &Path, diff_text: Option<&str>) -> Vec<&'static str> {
    if !needs_dependency_diff(path) {
        return Vec::new();
    }

    let diff_text = diff_text.unwrap_or_default();
    MIDEN_PROTOCOL_DEPENDENCIES
        .iter()
        .copied()
        .filter(|dependency| dependency_is_changed(path, diff_text, dependency))
        .collect()
}

fn dependency_is_changed(path: &Path, diff_text: &str, dependency: &str) -> bool {
    diff_text.lines().any(|line| {
        if line.starts_with("+++") || line.starts_with("---") {
            return false;
        }

        if path == Path::new("Cargo.lock") {
            return line.contains(dependency);
        }

        (line.starts_with('+') || line.starts_with('-')) && line.contains(dependency)
    })
}

fn is_deployment_change(path: &Path) -> bool {
    let path = path_string(path);
    path == "Dockerfile"
        || path.starts_with("Dockerfile.")
        || path == "docker-compose.yml"
        || path.starts_with("compose/")
        || path.starts_with("docker/")
        || path == ".github/workflows/build-docker.yml"
        || path == ".github/workflows/publish-docker.yml"
        || path == ".github/workflows/publish-debian.yml"
        || path == ".github/workflows/publish-debian-all.yml"
}

fn is_operator_docs_change(path: &Path) -> bool {
    has_prefix(path, "docs/external/src/full-node")
        || has_prefix(path, "docs/external/src/network-operator")
        || has_prefix(path, "docs/external/src/rpc")
        || path == Path::new("docs/external/src/local-network-development.md")
        || path == Path::new("docs/external/src/official-network-urls.md")
}

fn is_database_config_change(path: &Path) -> bool {
    has_prefix(path, "crates/store/src/db/migrations")
        || has_prefix(path, "crates/store/src/genesis/config")
}

fn has_prefix(path: &Path, prefix: &str) -> bool {
    path.starts_with(Path::new(prefix))
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_command_files_trigger_changelog() {
        let triggers = classify_path(Path::new("bin/node/src/commands/store.rs"), None, None);

        assert_eq!(triggers[0].kind, TriggerKind::Cli);
    }

    #[test]
    fn non_cli_binary_files_do_not_trigger_changelog() {
        let triggers = classify_path(Path::new("bin/ntx-builder/src/actor/execute.rs"), None, None);

        assert!(triggers.is_empty());
    }

    #[test]
    fn clap_files_trigger_changelog_even_outside_command_paths() {
        let triggers = classify_path(
            Path::new("bin/network-monitor/src/config.rs"),
            Some("use clap::Parser;\n#[derive(Parser)]\nstruct Config;"),
            None,
        );

        assert_eq!(triggers[0].kind, TriggerKind::Cli);
    }

    #[test]
    fn root_miden_protocol_dependency_changes_trigger_changelog() {
        let triggers = classify_path(
            Path::new("Cargo.toml"),
            None,
            Some(
                "-miden-protocol = { version = \"0.15\" }\n+miden-protocol = { version = \"0.16\" }\n",
            ),
        );

        assert_eq!(triggers[0].kind, TriggerKind::MidenProtocolDependency);
        assert_eq!(triggers[0].details, vec!["miden-protocol"]);
    }

    #[test]
    fn lockfile_miden_protocol_version_changes_trigger_changelog() {
        let triggers = classify_path(
            Path::new("Cargo.lock"),
            None,
            Some(
                r#"[[package]]
name = "miden-protocol"
-version = "0.15.0"
+version = "0.16.0"
"#,
            ),
        );

        assert_eq!(triggers[0].kind, TriggerKind::MidenProtocolDependency);
        assert_eq!(triggers[0].details, vec!["miden-protocol"]);
    }

    #[test]
    fn package_toml_feature_changes_do_not_trigger_dependency_heuristic() {
        let triggers = classify_path(
            Path::new("bin/node/Cargo.toml"),
            None,
            Some("+tracing-forest = [\"miden-node-block-producer/tracing-forest\"]\n"),
        );

        assert!(triggers.is_empty());
    }

    #[test]
    fn external_dependency_changes_do_not_trigger_changelog() {
        let triggers = classify_path(
            Path::new("Cargo.lock"),
            None,
            Some("-name = \"tonic\"\n+name = \"tonic\"\n"),
        );

        assert!(triggers.is_empty());
    }
}
