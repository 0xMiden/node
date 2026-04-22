use miden_protocol::Word;
use miden_protocol::account::AccountId;

use crate::decode::{ConversionResultExt, GrpcStructDecoder};
use crate::errors::ConversionError;
use crate::{decode, generated as proto};

/// Reads a block range from a request, returning a specific error type if the field is missing
pub fn read_block_range<E>(
    block_range: Option<proto::rpc::BlockRange>,
    entity: &'static str,
) -> Result<proto::rpc::BlockRange, E>
where
    E: From<ConversionError>,
{
    block_range.ok_or_else(|| {
        ConversionError::message(format!("{entity}: missing field `block_range`")).into()
    })
}

/// Reads and converts a root field from a request to Word, returning a specific error type if
/// conversion fails
pub fn read_root<E>(
    root: Option<proto::primitives::Digest>,
    entity: &'static str,
) -> Result<Word, E>
where
    E: From<ConversionError>,
{
    root.ok_or_else(|| ConversionError::message(format!("{entity}: missing field `root`")))?
        .try_into()
        .context("root")
        .map_err(|e: ConversionError| e.into())
}

/// Converts a collection of proto primitives to Words, returning a specific error type if
/// conversion fails
pub fn convert_digests_to_words<E, I>(digests: I) -> Result<Vec<Word>, E>
where
    E: From<ConversionError>,
    I: IntoIterator,
    I::Item: TryInto<Word, Error = ConversionError>,
{
    digests
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, ConversionError>>()
        .context("digests")
        .map_err(Into::into)
}

/// Reads account IDs from a request, returning a specific error type if conversion fails
pub fn read_account_ids<E, I>(account_ids: I) -> Result<Vec<AccountId>, E>
where
    E: From<ConversionError>,
    I: IntoIterator<Item = proto::account::AccountId>,
{
    account_ids
        .into_iter()
        .map(AccountId::try_from)
        .collect::<Result<_, ConversionError>>()
        .context("account_ids")
        .map_err(Into::into)
}

pub fn read_account_id<M: crate::prost::Message, E>(
    account_id: Option<proto::account::AccountId>,
) -> Result<AccountId, E>
where
    E: From<ConversionError>,
{
    let decoder = GrpcStructDecoder::<M>::default();
    decode!(decoder, account_id).map_err(|e: ConversionError| e.into())
}
