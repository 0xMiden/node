pub mod account;
pub mod batch;
pub mod block;
pub mod digest;
pub mod merkle;
pub mod note;
pub mod nullifier;
pub mod proof_request;
pub mod transaction;

// UTILITIES
// ================================================================================================

pub fn convert<T, From, To>(from: T) -> impl Iterator<Item = To>
where
    T: IntoIterator<Item = From>,
    From: Into<To>,
{
    from.into_iter().map(Into::into)
}

pub fn try_convert<T, E, From, To>(from: T) -> impl Iterator<Item = Result<To, E>>
where
    T: IntoIterator<Item = From>,
    From: TryInto<To, Error = E>,
{
    from.into_iter().map(TryInto::try_into)
}
