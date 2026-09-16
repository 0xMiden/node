use std::process::Command;

#[test]
fn help_lists_service_lifecycle_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-note-transport"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["bootstrap", "migrate", "start"] {
        assert!(help.contains(command), "missing command: {command}");
    }
}

#[test]
fn lifecycle_requires_explicit_initialization_and_preserves_existing_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite3");
    let run = |command: &str| {
        Command::new(env!("CARGO_BIN_EXE_miden-note-transport"))
            .args([command, "--database"])
            .arg(&path)
            .output()
            .unwrap()
    };
    assert!(!run("migrate").status.success());
    assert!(!path.exists());
    assert!(run("bootstrap").status.success());
    assert!(!run("bootstrap").status.success());
    assert!(run("migrate").status.success());
    assert!(!run("cleanup").status.success());
}

#[test]
fn start_requires_a_storage_limit() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-note-transport"))
        .args(["start", "--database", "unused.sqlite3"])
        .env_remove("MIDEN_NOTE_TRANSPORT_MAX_STORAGE_BYTES")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr).unwrap().contains("--max-storage-bytes"));
}

#[test]
fn cleanup_command_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-note-transport"))
        .args(["cleanup", "--help"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr).unwrap().contains("unrecognized subcommand"));
}

#[test]
fn start_help_exposes_retention_policy() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-note-transport"))
        .args(["start", "--help"])
        .env_remove("MIDEN_NOTE_TRANSPORT_RETENTION_DAYS")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--retention-days"));
    assert!(help.contains("MIDEN_NOTE_TRANSPORT_RETENTION_DAYS"));
    assert!(help.contains("[default: 30]"));
}

#[test]
fn start_reads_retention_environment_and_cli_takes_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.sqlite3");
    let run = |environment: &str, retention: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_miden-note-transport"));
        command
            .args(["start", "--database"])
            .arg(&path)
            .args(["--max-storage-bytes", "1024"])
            .env("MIDEN_NOTE_TRANSPORT_RETENTION_DAYS", environment);
        if let Some(retention) = retention {
            command.args(["--retention-days", retention]);
        }
        command.output().unwrap()
    };
    let output = run("invalid", None);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr).unwrap().contains("--retention-days"));
    for value in ["0", "7", "4294967295"] {
        for output in [run("invalid", Some(value)), run(value, None)] {
            assert_eq!(output.status.code(), Some(1));
            assert!(!String::from_utf8(output.stderr).unwrap().contains("invalid value"));
        }
    }
    assert!(!path.exists());
}
