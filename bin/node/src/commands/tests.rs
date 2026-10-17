use clap::Parser;
use clap::error::ErrorKind;

use super::Command;
use crate::Cli;

fn parse_full(source: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(
        [
            "miden-node",
            "full",
            "--data-directory",
            "node-data",
            "--rpc.listen",
            "127.0.0.1:57291",
        ]
        .into_iter()
        .chain(source.iter().copied()),
    )
}

#[test]
fn full_node_syncs_from_official_networks() {
    for (network, expected_url) in [
        ("mainnet", "https://rpc.mainnet.miden.io/"),
        ("testnet", "https://rpc.testnet.miden.io/"),
        ("devnet", "https://rpc.devnet.miden.io/"),
    ] {
        let cli = parse_full(&["--network", network]).unwrap();
        let Command::Full(command) = cli.command else {
            panic!("expected full node command");
        };
        assert_eq!(command.sync.block_source_url().as_str(), expected_url);
    }
}

#[test]
fn full_node_accepts_custom_sync_source() {
    let url = "http://upstream-node:57291/";
    let cli = parse_full(&["--sync.block-source.url", url]).unwrap();
    let Command::Full(command) = cli.command else {
        panic!("expected full node command");
    };
    assert_eq!(command.sync.block_source_url().as_str(), url);
}

#[test]
fn full_node_requires_exactly_one_sync_source() {
    assert_eq!(parse_full(&[]).unwrap_err().kind(), ErrorKind::MissingRequiredArgument);
    assert_eq!(
        parse_full(&[
            "--network",
            "mainnet",
            "--sync.block-source.url",
            "http://upstream-node:57291",
        ])
        .unwrap_err()
        .kind(),
        ErrorKind::ArgumentConflict,
    );
    assert_eq!(
        parse_full(&["--network", "unknown"]).unwrap_err().kind(),
        ErrorKind::InvalidValue,
    );
}

#[test]
fn bootstrap_accepts_mainnet_and_requires_exactly_one_genesis_source() {
    let args = ["miden-node", "bootstrap", "--data-directory", "node-data"];
    let cli = Cli::try_parse_from(args.into_iter().chain(["--network", "mainnet"])).unwrap();
    assert!(matches!(cli.command, Command::Bootstrap(_)));
    assert_eq!(
        Cli::try_parse_from(args).unwrap_err().kind(),
        ErrorKind::MissingRequiredArgument,
    );
    assert_eq!(
        Cli::try_parse_from(args.into_iter().chain([
            "--network",
            "mainnet",
            "--genesis",
            "genesis.dat"
        ]),)
        .unwrap_err()
        .kind(),
        ErrorKind::ArgumentConflict,
    );
}
