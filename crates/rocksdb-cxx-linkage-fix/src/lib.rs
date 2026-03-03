//! A temporary solution to missing c++ std library linkage when using a precompile static library
//!
//! For more information see: <https://github.com/rust-rocksdb/rust-rocksdb/pull/1029>

use std::env;

pub fn configure() {
    println!("cargo:rerun-if-env-changed=ROCKSDB_COMPILE");
    println!("cargo:rerun-if-env-changed=ROCKSDB_LIB_DIR");
    println!("cargo:rerun-if-env-changed=ROCKSDB_STATIC");
    println!("cargo:rerun-if-env-changed=CXXSTDLIB");
    let target = env::var("TARGET").unwrap_or_default();
    if should_link_cpp_stdlib() {
        link_cpp_stdlib(&target);
    }
}

fn should_compile() -> bool {
    // in sync with <https://github.com/rust-rocksdb/rust-rocksdb/blob/master/librocksdb-sys/build.rs#L348-L352>
    if let Ok(v) = env::var("ROCKSDB_COMPILE") {
        if v.to_lowercase() == "true" || v == "1" {
            return true;
        }
    }
    false
}

fn should_link_cpp_stdlib() -> bool {
    if should_compile() {
        return false;
    }
    // the value doesn't matter
    // <https://github.com/rust-rocksdb/rust-rocksdb/blob/master/librocksdb-sys/build.rs#L359>
    env::var("ROCKSDB_STATIC").is_ok()
    // `ROCKSDB_LIB_DIR` is not really discriminative, it only adds extra lookup dirs for the linker
}

fn link_cpp_stdlib(target: &str) {
    // aligned with
    // <https://github.com/rust-rocksdb/rust-rocksdb/blob/master/librocksdb-sys/build.rs#L399-L411>
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
