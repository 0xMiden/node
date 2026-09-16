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
