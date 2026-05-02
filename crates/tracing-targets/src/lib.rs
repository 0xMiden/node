use std::fmt::Write as _;
use std::str::FromStr;

use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};

#[derive(Clone, Copy, Debug, Eq, EnumIter, IntoStaticStr, PartialEq)]
pub enum TelemetryTarget {
    #[strum(serialize = "rpc")]
    Rpc,
    #[strum(serialize = "validator::database")]
    ValidatorDatabase,
    #[strum(serialize = "store::database")]
    StoreDatabase,
    #[strum(serialize = "store::forest")]
    StoreForest,
    #[strum(serialize = "store::grpc::server::rpc")]
    StoreGrpcServerRpc,
    #[strum(serialize = "store::grpc::server::ntx")]
    StoreGrpcServerNtx,
    #[strum(serialize = "store::grpc::server::sequencer")]
    StoreGrpcServerSequencer,
    #[strum(serialize = "sequencer::batch_builder")]
    SequencerBatchBuilder,
    #[strum(serialize = "sequencer::block_builder")]
    SequencerBlockBuilder,
    #[strum(serialize = "sequencer::mempool")]
    SequencerMempool,
    #[strum(serialize = "ntxb::coordinator")]
    NtxbCoordinator,
    #[strum(serialize = "ntxb::actor")]
    NtxbActor,
    #[strum(serialize = "ntxb::database")]
    NtxbDatabase,
}

impl TelemetryTarget {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl FromStr for TelemetryTarget {
    type Err = UnknownTelemetryTarget;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::iter()
            .find(|target| target.as_str() == value)
            .ok_or_else(|| UnknownTelemetryTarget(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownTelemetryTarget(String);

impl std::fmt::Display for UnknownTelemetryTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown telemetry target `{}`", self.0)
    }
}

impl std::error::Error for UnknownTelemetryTarget {}

pub fn allowed_targets() -> impl Iterator<Item = &'static str> {
    TelemetryTarget::iter().map(TelemetryTarget::as_str)
}

pub fn allowed_targets_list() -> String {
    let mut targets = String::new();
    for target in allowed_targets() {
        write!(targets, "\n  - {target}").expect("writing to String should not fail");
    }
    targets
}

pub fn is_allowed_application_target(target: &str) -> bool {
    allowed_targets().any(|allowed| {
        target == allowed
            || target.strip_prefix(allowed).is_some_and(|suffix| suffix.starts_with("::"))
    })
}

pub fn is_allowed_target_filter(target: &str) -> bool {
    is_allowed_application_target(target)
        || allowed_targets().any(|allowed| {
            allowed.strip_prefix(target).is_some_and(|suffix| suffix.starts_with("::"))
        })
}

pub fn parse_allowed_target(target: &str) -> Result<TelemetryTarget, UnknownTelemetryTarget> {
    target.parse()
}
