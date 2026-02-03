//! A temporary solution to missing c++ std library linkage when using a precompile static library
//!
//! For more information see: <https://github.com/rust-rocksdb/rust-rocksdb/pull/1029>

use std::env;

pub fn configure() {
    println!("cargo:rerun-if-env-changed=ROCKSDB_COMPILE");
    println!("cargo:rerun-if-env-changed=ROCKSDB_STATIC");
    println!("cargo:rerun-if-env-changed=CXXSTDLIB");
    let target = env::var("TARGET").unwrap_or_default();
    if should_link_cpp_stdlib() {
        link_cpp_stdlib(&target);
    }
}

fn should_link_cpp_stdlib() -> bool {
    let rocksdb_compile = env::var("ROCKSDB_COMPILE").unwrap_or_default();
    let rocksdb_compile_disabled = matches!(rocksdb_compile.as_str(), "0" | "false" | "FALSE");
    let rocksdb_static = env::var("ROCKSDB_STATIC").is_ok();

    rocksdb_compile_disabled && rocksdb_static
}

fn link_cpp_stdlib(target: &str) {
    if let Ok(stdlib) = env::var("CXXSTDLIB") {
        println!("cargo:rustc-link-lib=dylib={stdlib}");
    } else if target.contains("apple") || target.contains("freebsd") || target.contains("openbsd") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else if target.contains("aix") {
        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=dylib=c++abi");
    }
}
