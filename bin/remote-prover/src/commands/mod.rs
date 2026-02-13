use clap::Parser;
use worker::StartWorker;

pub mod worker;

/// CLI actions
#[derive(Debug, Parser)]
pub enum Command {
    /// Starts the workers with the configuration defined in the command.
    StartWorker(StartWorker),
}
