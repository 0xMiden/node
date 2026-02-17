// This build.rs is required to trigger the `diesel_migrations::embed_migrations!` proc-macro in
// `validator/src/db/migrations.rs` to include the latest version of the migrations into the binary, see <https://docs.rs/diesel_migrations/latest/diesel_migrations/macro.embed_migrations.html#automatic-rebuilds>.
fn main() {
    println!("cargo:rerun-if-changed=./src/db/migrations");
    // If we do one re-write, the default rules are disabled,
    // hence we need to trigger explicitly on `Cargo.toml`.
    // <https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed>
    println!("cargo:rerun-if-changed=Cargo.toml");
}
