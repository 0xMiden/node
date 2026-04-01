use clap::Parser;

use crate::Cli;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("miden-node").chain(args.iter().copied()))
}

#[test]
fn store_bootstrap_parses() {
    let _ = parse(&["store", "bootstrap"]);
}

#[test]
fn block_producer_start_parses() {
    let _ = parse(&["block-producer", "start"]);
}

#[test]
fn validator_bootstrap_parses() {
    let _ = parse(&["validator", "bootstrap"]);
}

#[test]
fn validator_start_parses() {
    let _ = parse(&["validator", "start"]);
}

#[test]
fn bundled_bootstrap_parses() {
    let _ = parse(&["bundled", "bootstrap"]);
}

#[test]
fn bundled_start_parses() {
    let _ = parse(&["bundled", "start"]);
}

#[test]
fn bundled_start_with_max_cycles_parses() {
    let max_cycles = 2_i32.pow(18).to_string();
    let _ = parse(&["bundled", "start", "--ntx-builder.max-cycles", &max_cycles]);
}
