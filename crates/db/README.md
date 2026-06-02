# Miden node DB

`db` contains shared SQLite database infrastructure for the Miden node workspace. It is part of the
[Miden node](https://github.com/0xMiden/node#readme) repository.

## Role

This crate provides database connection management, transaction helpers, schema verification, and migration
infrastructure shared by node services that persist local state.

It is an implementation crate used by binaries and component crates, not a standalone operator entry point.

## License

This project is [MIT licensed](../../LICENSE).
