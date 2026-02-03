//! Central place to define conversion from and to database primitive types
//!
//! Eventually, all of them should have types and we can implement a trait for them
//! rather than function pairs.
//!
//! Notice: All of them are infallible. The invariant is a sane content of the database
//! and humans ensure the sanity of casts.
//!
//! Notice: Keep in mind if you _need_ to expand the datatype, only if you require sorting this is
//! mandatory!
//!
//! Notice: Ensure you understand what casting does at the bit-level before changing any.
//!
//! Notice: Changing any of these are _backwards-incompatible_ changes that are not caught/covered
//! by migrations!

#![allow(
    clippy::inline_always,
    reason = "Just unification helpers of 1-2 lines of casting types"
)]
#![allow(
    dead_code,
    reason = "Not all converters are used bidirectionally, however, keeping them is a good thing"
)]
#![allow(
    clippy::cast_sign_loss,
    reason = "This is the one file where we map the signed database types to the working types"
)]
#![allow(
    clippy::cast_possible_wrap,
    reason = "We will not approach the item count where i64 and usize casting will cause issues
    on relevant platforms"
)]

use miden_protocol::Felt;
use miden_protocol::account::{StorageSlotName, StorageSlotType};
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteTag;

use crate::db::models::queries::NetworkAccountType;

#[derive(Debug, thiserror::Error)]
#[error("failed to convert from database type {from_type} into {into_type}")]
pub struct DatabaseTypeConversionError {
    source: Box<dyn std::error::Error + Send + Sync>,
    from_type: &'static str,
    into_type: &'static str,
}

/// Convert from and to it's database representation and back
///
/// We do not assume sanity of DB types.
pub trait SqlTypeConvert: Sized {
    type Raw: Sized;

    fn to_raw_sql(self) -> Self::Raw;
    fn from_raw_sql(_raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError>;

    fn map_err<E: std::error::Error + Send + Sync + 'static>(
        source: E,
    ) -> DatabaseTypeConversionError {
        DatabaseTypeConversionError {
            source: Box::new(source),
            from_type: std::any::type_name::<Self::Raw>(),
            into_type: std::any::type_name::<Self>(),
        }
    }
}

impl SqlTypeConvert for NetworkAccountType {
    type Raw = i32;

    fn to_raw_sql(self) -> Self::Raw {
        match self {
            NetworkAccountType::None => 0,
            NetworkAccountType::Network => 1,
        }
    }

    fn from_raw_sql(raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError> {
        #[derive(Debug, thiserror::Error)]
        #[error("invalid network account type value {0}")]
        struct ValueError(i32);

        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Network),
            other => Err(Self::map_err(ValueError(other))),
        }
    }
}

impl SqlTypeConvert for BlockNumber {
    type Raw = i64;

    fn from_raw_sql(raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError> {
        u32::try_from(raw).map(BlockNumber::from).map_err(Self::map_err)
    }

    fn to_raw_sql(self) -> Self::Raw {
        i64::from(self.as_u32())
    }
}

impl SqlTypeConvert for NoteTag {
    type Raw = i32;

    #[inline(always)]
    fn from_raw_sql(raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError> {
        #[allow(clippy::cast_sign_loss)]
        Ok(NoteTag::new(raw as u32))
    }

    #[inline(always)]
    fn to_raw_sql(self) -> Self::Raw {
        self.as_u32() as i32
    }
}

impl SqlTypeConvert for StorageSlotType {
    type Raw = i32;

    #[inline(always)]
    fn from_raw_sql(raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError> {
        #[derive(Debug, thiserror::Error)]
        #[error("invalid storage slot type value {0}")]
        struct ValueError(i32);

        Ok(match raw {
            0 => StorageSlotType::Value,
            1 => StorageSlotType::Map,
            invalid => {
                return Err(Self::map_err(ValueError(invalid)));
            },
        })
    }

    #[inline(always)]
    fn to_raw_sql(self) -> Self::Raw {
        match self {
            StorageSlotType::Value => 0,
            StorageSlotType::Map => 1,
        }
    }
}

impl SqlTypeConvert for StorageSlotName {
    type Raw = String;

    fn from_raw_sql(raw: Self::Raw) -> Result<Self, DatabaseTypeConversionError> {
        StorageSlotName::new(raw).map_err(Self::map_err)
    }

    fn to_raw_sql(self) -> Self::Raw {
        String::from(self)
    }
}

// Raw type conversions - eventually introduce wrapper types
// ===========================================================

#[inline(always)]
pub(crate) fn raw_sql_to_nullifier_prefix(raw: i32) -> u16 {
    debug_assert!(raw >= 0);
    raw as u16
}
#[inline(always)]
pub(crate) fn nullifier_prefix_to_raw_sql(prefix: u16) -> i32 {
    i32::from(prefix)
}

#[inline(always)]
pub(crate) fn raw_sql_to_nonce(raw: i64) -> Felt {
    debug_assert!(raw >= 0);
    Felt::new(raw as u64)
}
#[inline(always)]
pub(crate) fn nonce_to_raw_sql(nonce: Felt) -> i64 {
    nonce.as_int() as i64
}

#[inline(always)]
pub(crate) fn raw_sql_to_fungible_delta(raw: i64) -> i64 {
    raw
}
#[inline(always)]
pub(crate) fn fungible_delta_to_raw_sql(delta: i64) -> i64 {
    delta
}

#[inline(always)]
#[allow(clippy::cast_sign_loss)]
pub(crate) fn raw_sql_to_note_type(raw: i32) -> u8 {
    raw as u8
}
#[inline(always)]
pub(crate) fn note_type_to_raw_sql(note_type: u8) -> i32 {
    i32::from(note_type)
}

#[inline(always)]
pub(crate) fn raw_sql_to_idx(raw: i32) -> usize {
    raw as usize
}
#[inline(always)]
pub(crate) fn idx_to_raw_sql(idx: usize) -> i32 {
    idx as i32
}
