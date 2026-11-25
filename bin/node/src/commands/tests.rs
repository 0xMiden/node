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

#[test]
fn grpc_commands_accept_one_process_decoding_limit() {
    for args in [
        vec![
            "full",
            "--data-directory",
            "node-data",
            "--rpc.listen",
            "127.0.0.1:57291",
            "--network",
            "testnet",
        ],
        vec![
            "sequencer",
            "--data-directory",
            "node-data",
            "--rpc.listen",
            "127.0.0.1:57291",
            "--validator.url",
            "http://localhost:50051",
            "--ntx-builder.url",
            "http://localhost:50052",
            "--batch.builder.wallet-account-id",
            "0xcc0000000000dd010000ee000000ff",
        ],
        vec![
            "recover",
            "--data-directory",
            "node-data",
            "--validator.url",
            "http://localhost:50051",
        ],
        vec![
            "fee-collector",
            "deploy",
            "--data-directory",
            "node-data",
            "--validator.url",
            "http://localhost:50051",
        ],
    ] {
        let parsed = Cli::try_parse_from(
            std::iter::once("miden-node")
                .chain(args.iter().copied())
                .chain(["--grpc.max-decoding-message-size", "16777216"]),
        );
        assert!(parsed.is_ok(), "{parsed:?}");
    }
}

#[test]
fn full_node_admin_listener_is_opt_in() {
    let cli = parse_full(&["--network", "testnet"]).unwrap();
    let Command::Full(command) = cli.command else {
        panic!("expected full node command");
    };
    assert_eq!(command.admin.listen, None);
    let cli = parse_full(&["--network", "testnet", "--admin.listen", "127.0.0.1:50100"]).unwrap();
    let Command::Full(command) = cli.command else {
        panic!("expected full node command");
    };
    assert_eq!(command.admin.listen, Some("127.0.0.1:50100".parse().unwrap()));
}

#[test]
fn sequencer_batch_prover_is_optional_and_independent_of_the_block_prover() {
    let base = [
        "miden-node",
        "sequencer",
        "--data-directory",
        "node-data",
        "--rpc.listen",
        "127.0.0.1:57291",
        "--validator.url",
        "http://localhost:50051",
        "--ntx-builder.url",
        "http://localhost:50052",
        "--batch.builder.wallet-account-id",
        "0xcc0000000000dd010000ee000000ff",
    ];
    for (extra, expected) in [
        (vec![], None),
        (
            vec!["--batch-prover.url", "http://batch-prover:50051"],
            Some("http://batch-prover:50051/"),
        ),
    ] {
        let cli = Cli::try_parse_from(base.into_iter().chain(extra)).unwrap();
        let Command::Sequencer(command) = cli.command else {
            panic!("expected sequencer")
        };
        assert_eq!(
            command.block_producer.batch_prover.url.as_ref().map(url::Url::as_str),
            expected
        );
        assert_eq!(command.block_producer.block_prover.url, None);
    }
    assert!(
        Cli::try_parse_from(base.into_iter().chain(["--batch-prover.url", "not-a-url"])).is_err()
    );
}

#[tokio::test]
async fn occupied_admin_port_prevents_sequencer_startup() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let directory = tempfile::tempdir().unwrap();
    let data_directory = directory.path().join("not-initialized");
    let cli = Cli::try_parse_from([
        "miden-node",
        "sequencer",
        "--data-directory",
        data_directory.to_str().unwrap(),
        "--rpc.listen",
        "127.0.0.1:0",
        "--admin.listen",
        &address,
        "--validator.url",
        "http://localhost:50051",
        "--ntx-builder.url",
        "http://localhost:50052",
        "--batch.builder.wallet-account-id",
        "0xcc0000000000dd010000ee000000ff",
    ])
    .unwrap();
    let Command::Sequencer(command) = cli.command else {
        panic!("expected sequencer")
    };
    let error = command
        .handle(miden_node_utils::shutdown::CancellationToken::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("failed to bind admin listener"), "{error:#}");
    assert!(!data_directory.exists());
}
