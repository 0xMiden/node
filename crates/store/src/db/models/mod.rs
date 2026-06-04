//! Defines models for usage with the diesel API
//!
//! Note: `select` can either be used as
//! `SelectDsl::select(schema::foo::table, (schema::foo::some_cool_id, ))`
//! or
//! `SelectDsl::select(schema::foo::table, FooRawRow::as_selectable())`.
//!
//! The former can be used to avoid declaring extra types, while the latter
//! is better if a full row is in need of loading and avoids duplicate
//! specification.
//!
//! Note: The fully qualified syntax yields for _much_ better errors.
//! The first step in debugging should always be using the fully qualified
//! calling syntext when dealing with diesel.

#[cfg(test)]
use std::num::NonZeroUsize;

use crate::errors::DatabaseError;

pub(crate) mod conv;

pub mod queries;
pub(crate) mod utils;

pub(crate) use utils::*;

/// The page token and size to query from the DB.
#[cfg(test)]
#[derive(Debug, Copy, Clone)]
pub struct Page {
    pub token: Option<u64>,
    pub size: NonZeroUsize,
}
