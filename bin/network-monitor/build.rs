use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use miden_protocol::assembly::diagnostics::NamedSource;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::serde::Serializable;

const COUNTER_MODULE_PATH: &str = "miden::monitor::counter_contract";

fn main() {
    println!("cargo::rerun-if-changed=src/assets/counter_program.masm");
    println!("cargo::rerun-if-changed=src/assets/increment_counter.masm");
    println!("cargo::rerun-if-changed=src/assets/counter-contract/Cargo.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-contract/rust-toolchain.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-contract/.cargo/config.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-contract/src/lib.rs");
    println!("cargo::rerun-if-changed=src/assets/counter-note/Cargo.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-note/rust-toolchain.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-note/.cargo/config.toml");
    println!("cargo::rerun-if-changed=src/assets/counter-note/src/lib.rs");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));
    let out_dir_str = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let out_dir = Path::new(&out_dir_str);

    if has_cargo_miden() {
        let counter_project_dir = manifest_dir.join("src/assets/counter-contract");
        let note_project_dir = manifest_dir.join("src/assets/counter-note");
        let counter_package = compile_miden_project(&counter_project_dir, "counter-contract");
        let note_package = compile_miden_project(&note_project_dir, "counter-note");

        fs_err::copy(counter_package, out_dir.join("counter_contract.masp"))
            .expect("copying counter contract package should succeed");
        fs_err::copy(note_package, out_dir.join("counter_note.masp"))
            .expect("copying counter note package should succeed");
        println!("cargo::rustc-cfg=compiled_miden_rust_assets");
    } else {
        println!(
            "cargo::warning=cargo-miden not found; using checked-in MASM fallback assets for the network monitor counter"
        );
        compile_masm_fallback(out_dir);
    }
    println!("cargo::rustc-check-cfg=cfg(compiled_miden_rust_assets)");
}

fn compile_miden_project(project_dir: &Path, package_name: &str) -> PathBuf {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .current_dir(project_dir)
        .args(["miden", "build", "--release"])
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "failed to run `cargo miden build --release` in {}: {err}",
                project_dir.display()
            )
        });

    assert!(
        output.status.success(),
        "`cargo miden build --release` failed in {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        project_dir.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let package_path = project_dir
        .join("target/miden/release")
        .join(package_name)
        .with_extension("masp");
    assert!(
        package_path.exists(),
        "`cargo miden build --release` did not produce {}",
        package_path.display()
    );
    package_path
}

fn has_cargo_miden() -> bool {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    Command::new(cargo)
        .args(["miden", "--version"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile_masm_fallback(out_dir: &Path) {
    let counter_masm = fs_err::read_to_string("src/assets/counter_program.masm")
        .expect("src/assets/counter_program.masm must exist");
    let note_masm = fs_err::read_to_string("src/assets/increment_counter.masm")
        .expect("src/assets/increment_counter.masm must exist");

    let assembler = TransactionKernel::assembler().with_warnings_as_errors(true);

    let counter_lib = assembler
        .clone()
        .assemble_library([NamedSource::new(COUNTER_MODULE_PATH, counter_masm)])
        .expect("counter_program.masm should compile without errors");

    counter_lib
        .write_to_file(out_dir.join("counter_program.masl"))
        .expect("writing counter_program.masl should succeed");

    let mut note_assembler = assembler;
    note_assembler
        .link_static_library(Arc::as_ref(&counter_lib))
        .expect("linking counter library into note assembler should succeed");

    let note_program = note_assembler
        .assemble_program(note_masm)
        .expect("increment_counter.masm should compile without errors");

    let note_script_bytes = NoteScript::new(note_program).to_bytes();
    fs_err::write(out_dir.join("increment_note_script.bin"), note_script_bytes)
        .expect("writing increment_note_script.bin should succeed");
}
