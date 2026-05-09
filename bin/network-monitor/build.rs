use std::env;
use std::path::Path;
use std::sync::Arc;

use miden_protocol::assembly::diagnostics::NamedSource;
use miden_protocol::note::NoteScript;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::serde::Serializable;

const COUNTER_MODULE_PATH: &str = "miden::monitor::counter_contract";

fn main() {
    println!("cargo::rerun-if-changed=src/assets/counter_program.masm");
    println!("cargo::rerun-if-changed=src/assets/increment_counter.masm");

    let out_dir_str = env::var("OUT_DIR").expect("OUT_DIR must be set");
    let out_dir = Path::new(&out_dir_str);

    let counter_masm = std::fs::read_to_string("src/assets/counter_program.masm")
        .expect("src/assets/counter_program.masm must exist");
    let note_masm = std::fs::read_to_string("src/assets/increment_counter.masm")
        .expect("src/assets/increment_counter.masm must exist");

    let assembler = TransactionKernel::assembler().with_warnings_as_errors(true);

    // Compile counter program to a library (.masl).
    let counter_lib = assembler
        .clone()
        .assemble_library([NamedSource::new(COUNTER_MODULE_PATH, counter_masm)])
        .expect("counter_program.masm should compile without errors");

    counter_lib
        .write_to_file(out_dir.join("counter_program.masl"))
        .expect("writing counter_program.masl should succeed");

    // Compile note script statically linked against the counter library.
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
