fn main() -> Result<(), Box<dyn std::error::Error>> {
    miden_node_db::migration::Migrator::generate("src/db/migrations", "db_migrator.rs")?;
    println!("cargo:rerun-if-changed=Cargo.toml");
    Ok(())
}
