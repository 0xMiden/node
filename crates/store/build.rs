fn main() -> Result<(), Box<dyn std::error::Error>> {
    miden_node_db::migration::Migrator::generate("src/db/migrations")?;

    // If we do one re-write, the default rules are disabled,
    // hence we need to trigger explicitly on `Cargo.toml`.
    // <https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed>
    build_rs::output::rerun_if_changed("Cargo.toml");

    Ok(())
}
