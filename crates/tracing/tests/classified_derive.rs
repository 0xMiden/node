use miden_node_tracing::{Classified, FailureClass};

#[derive(Debug, thiserror::Error, Classified)]
#[failure(transient)]
enum Fetch {
    #[error("timed out")]
    TimedOut,
    #[error("refused")]
    #[failure(rejected)]
    Refused { reason: String },
}

fn by_status(status: &tonic::Status) -> FailureClass {
    FailureClass::from_grpc_code(status.code()).with_kind("checked")
}

#[derive(Debug, thiserror::Error, Classified)]
enum Submit {
    #[error("database failed")]
    DatabaseFailed(std::io::Error),
    #[error("fetch failed")]
    #[failure(transparent)]
    Fetch(#[source] Fetch),
    #[error("validator failed")]
    #[failure(dependency)]
    Validator { status: tonic::Status },
    #[error("check failed")]
    #[failure(with = by_status)]
    Check(tonic::Status),
}

#[test]
fn variants_use_their_snake_case_name_as_the_kind() {
    assert_eq!(Fetch::TimedOut.failure_class(), FailureClass::Transient("timed_out"));
    assert_eq!(
        Fetch::Refused { reason: String::new() }.failure_class(),
        FailureClass::Rejected("refused")
    );
    assert_eq!(
        Submit::DatabaseFailed(std::io::Error::other("disk")).failure_class(),
        FailureClass::Fault("database_failed")
    );
}

#[test]
fn variants_can_be_classified_by_their_field() {
    assert_eq!(
        Submit::Fetch(Fetch::TimedOut).failure_class(),
        FailureClass::Transient("timed_out")
    );
    assert_eq!(
        Submit::Validator {
            status: tonic::Status::invalid_argument("bad block")
        }
        .failure_class(),
        FailureClass::Fault("invalid_argument")
    );
    assert_eq!(
        Submit::Validator {
            status: tonic::Status::unavailable("down")
        }
        .failure_class(),
        FailureClass::Transient("unavailable")
    );
    assert_eq!(
        Submit::Check(tonic::Status::invalid_argument("bad")).failure_class(),
        FailureClass::Rejected("checked")
    );
}
