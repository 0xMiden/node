use clap::Parser;

use crate::{Cli, Command};

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("miden-node").chain(args.iter().copied()))
}

fn common_runtime_args() -> [&'static str; 7] {
    [
        "sequencer",
        "--data-directory",
        "/tmp/miden-node",
        "--rpc.listen",
        "127.0.0.1:57291",
        "--rpc.grpc.timeout",
        "10s",
    ]
}

#[test]
fn bootstrap_parses() {
    let cli = parse(&[
        "bootstrap",
        "--data-directory",
        "/tmp/miden-node",
        "--genesis-block",
        "/tmp/genesis.dat",
    ])
    .expect("bootstrap command should parse");

    assert!(matches!(cli.command, Command::Bootstrap(_)));
}

#[test]
fn migrate_parses() {
    let cli = parse(&["migrate", "--data-directory", "/tmp/miden-node"])
        .expect("migrate command should parse");

    assert!(matches!(cli.command, Command::Migrate(_)));
}

#[test]
fn sequencer_parses() {
    let cli = parse(&common_runtime_args()).expect("sequencer command should parse");

    assert!(matches!(cli.command, Command::Sequencer(_)));
}

#[test]
fn rpc_parses() {
    let mut args = common_runtime_args().to_vec();
    args[0] = "rpc";
    args.extend(["--sync.block-source.url", "http://127.0.0.1:50001"]);

    let cli = parse(&args).expect("rpc command should parse");

    assert!(matches!(cli.command, Command::Rpc(_)));
}

#[test]
fn runtime_external_service_urls_are_optional() {
    let cli =
        parse(&common_runtime_args()).expect("sequencer should not require external services");

    let Command::Sequencer(command) = cli.command else {
        panic!("expected sequencer command");
    };

    assert!(command.runtime.external_services.validator_url.is_none());
    assert!(command.runtime.external_services.ntx_builder_url.is_none());
}

#[test]
fn runtime_external_service_urls_parse_when_provided() {
    let mut args = common_runtime_args().to_vec();
    args.extend([
        "--validator.url",
        "http://127.0.0.1:50101",
        "--ntx-builder.url",
        "http://127.0.0.1:50301",
    ]);

    let Command::Sequencer(command) =
        parse(&args).expect("sequencer should accept external service urls").command
    else {
        panic!("expected sequencer command");
    };

    assert!(command.runtime.external_services.validator_url.is_some());
    assert!(command.runtime.external_services.ntx_builder_url.is_some());
}

#[test]
fn bootstrap_rejects_runtime_options() {
    parse(&[
        "bootstrap",
        "--data-directory",
        "/tmp/miden-node",
        "--genesis-block",
        "/tmp/genesis.dat",
        "--rpc.listen",
        "127.0.0.1:57291",
    ])
    .expect_err("bootstrap should not accept runtime options");
}

#[test]
fn migrate_rejects_runtime_options() {
    parse(&["migrate", "--data-directory", "/tmp/miden-node", "--enable-otel"])
        .expect_err("migrate should not accept runtime options");
}

#[test]
fn grouped_runtime_options_parse() {
    let mut args = common_runtime_args().to_vec();
    args.extend([
        "--rpc.rate-limit.burst-size",
        "256",
        "--rpc.rate-limit.replenish-per-second",
        "32",
        "--rpc.rate-limit.max-concurrent-connections",
        "2000",
        "--store.sqlite.connection-pool-size",
        "4",
        "--store.account-tree.rocksdb.cache-size",
        "1024",
        "--store.nullifier-tree.rocksdb.max-open-fds",
        "32",
        "--store.account-state-forest.rocksdb.durability-mode",
        "relaxed",
    ]);

    let cli = parse(&args).expect("grouped runtime options should parse");

    assert!(matches!(cli.command, Command::Sequencer(_)));
}

#[test]
fn old_component_commands_are_removed() {
    parse(&["store", "start"]).expect_err("store component command should be removed");
    parse(&["block-producer", "start"])
        .expect_err("block-producer component command should be removed");
    parse(&["rpc", "start"]).expect_err("rpc component start command should be removed");
}

#[test]
fn sequencer_rejects_too_large_max_batches_per_block() {
    let mut args = common_runtime_args().to_vec();
    let too_large = (miden_protocol::MAX_BATCHES_PER_BLOCK + 1).to_string();
    args.extend(["--block.max-batches", &too_large]);

    let Command::Sequencer(command) = parse(&args)
        .expect("sequencer command should parse before runtime validation")
        .command
    else {
        panic!("expected sequencer command");
    };

    let err = command
        .block_producer
        .validate()
        .expect_err("protocol limit should be enforced");

    assert!(err.to_string().contains("block.max-batches"));
}

#[test]
fn sequencer_rejects_too_large_max_txs_per_batch() {
    let mut args = common_runtime_args().to_vec();
    let too_large = (miden_protocol::MAX_ACCOUNTS_PER_BATCH + 1).to_string();
    args.extend(["--batch.max-txs", &too_large]);

    let Command::Sequencer(command) = parse(&args)
        .expect("sequencer command should parse before runtime validation")
        .command
    else {
        panic!("expected sequencer command");
    };

    let err = command
        .block_producer
        .validate()
        .expect_err("protocol limit should be enforced");

    assert!(err.to_string().contains("batch.max-txs"));
}
