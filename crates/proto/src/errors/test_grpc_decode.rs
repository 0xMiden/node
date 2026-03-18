//! Tests for the `#[grpc_decode]` attribute macro.
//!
//! Verifies that the macro correctly rewrites `.decode()` calls in function parameters,
//! closures, for-loops, and match arms.

use miden_protocol::{Felt, Word};

use crate::errors::{ConversionError, GrpcDecodeExt as _, grpc_decode};
use crate::generated as proto;

// HELPER
// ================================================================================================

/// Creates a valid `proto::primitives::Digest` that converts to `[Felt; 4]` without error.
fn valid_digest() -> proto::primitives::Digest {
    proto::primitives::Digest { d0: 1, d1: 2, d2: 3, d3: 4 }
}

// FUNCTION PARAMETER
// ================================================================================================

/// Wrapper to test basic function parameter decoding.
#[derive(Debug)]
struct DecodedEntry {
    key: Word,
    value: Word,
}

#[grpc_decode]
impl TryFrom<proto::primitives::SmtLeafEntry> for DecodedEntry {
    type Error = ConversionError;

    fn try_from(entry: proto::primitives::SmtLeafEntry) -> Result<Self, Self::Error> {
        let key: Word = entry.key.decode()?;
        let value: Word = entry.value.decode()?;
        Ok(Self { key, value })
    }
}

#[test]
fn test_function_param_decode() {
    let entry = proto::primitives::SmtLeafEntry {
        key: Some(valid_digest()),
        value: Some(valid_digest()),
    };
    let decoded = DecodedEntry::try_from(entry).unwrap();
    assert_eq!(decoded.key[0], Felt::new(1));
    assert_eq!(decoded.value[0], Felt::new(1));
}

#[test]
fn test_function_param_missing_field() {
    let entry = proto::primitives::SmtLeafEntry { key: None, value: Some(valid_digest()) };
    let err = DecodedEntry::try_from(entry).unwrap_err();
    assert!(
        err.to_string().contains("key") && err.to_string().contains("missing"),
        "expected missing key error, got: {err}",
    );
}

// CLOSURE
// ================================================================================================

/// Wrapper to test closure-based decoding (`.map(|item| item.field.decode())`).
#[derive(Debug)]
struct DecodedEntries {
    keys: Vec<Word>,
}

#[grpc_decode]
impl TryFrom<proto::primitives::SmtLeafEntryList> for DecodedEntries {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::SmtLeafEntryList) -> Result<Self, Self::Error> {
        let keys: Vec<Word> = value
            .entries
            .into_iter()
            .map(|entry| {
                let key: Word = entry.key.decode()?;
                Ok(key)
            })
            .collect::<Result<_, ConversionError>>()?;
        Ok(Self { keys })
    }
}

#[test]
fn test_closure_decode() {
    let entries = proto::primitives::SmtLeafEntryList {
        entries: vec![
            proto::primitives::SmtLeafEntry {
                key: Some(valid_digest()),
                value: Some(valid_digest()),
            },
            proto::primitives::SmtLeafEntry {
                key: Some(proto::primitives::Digest { d0: 10, d1: 20, d2: 30, d3: 40 }),
                value: Some(valid_digest()),
            },
        ],
    };
    let decoded = DecodedEntries::try_from(entries).unwrap();
    assert_eq!(decoded.keys.len(), 2);
    assert_eq!(decoded.keys[0][0], Felt::new(1));
    assert_eq!(decoded.keys[1][0], Felt::new(10));
}

#[test]
fn test_closure_decode_missing_field() {
    let entries = proto::primitives::SmtLeafEntryList {
        entries: vec![proto::primitives::SmtLeafEntry { key: None, value: Some(valid_digest()) }],
    };
    let err = DecodedEntries::try_from(entries).unwrap_err();
    assert!(
        err.to_string().contains("key") && err.to_string().contains("missing"),
        "expected missing key error, got: {err}",
    );
}

// FOR-LOOP
// ================================================================================================

/// Wrapper to test for-loop decoding.
#[derive(Debug)]
struct CollectedKeys {
    keys: Vec<Word>,
}

#[grpc_decode]
impl TryFrom<proto::primitives::SmtLeafEntryList> for CollectedKeys {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::SmtLeafEntryList) -> Result<Self, Self::Error> {
        let mut keys = Vec::new();
        for entry in value.entries {
            let key: Word = entry.key.decode()?;
            keys.push(key);
        }
        Ok(Self { keys })
    }
}

#[test]
fn test_for_loop_decode() {
    let entries = proto::primitives::SmtLeafEntryList {
        entries: vec![
            proto::primitives::SmtLeafEntry {
                key: Some(valid_digest()),
                value: Some(valid_digest()),
            },
            proto::primitives::SmtLeafEntry {
                key: Some(proto::primitives::Digest { d0: 5, d1: 6, d2: 7, d3: 8 }),
                value: Some(valid_digest()),
            },
        ],
    };
    let decoded = CollectedKeys::try_from(entries).unwrap();
    assert_eq!(decoded.keys.len(), 2);
    assert_eq!(decoded.keys[0][0], Felt::new(1));
    assert_eq!(decoded.keys[1][0], Felt::new(5));
}

#[test]
fn test_for_loop_decode_missing_field() {
    let entries = proto::primitives::SmtLeafEntryList {
        entries: vec![proto::primitives::SmtLeafEntry { key: None, value: None }],
    };
    let err = CollectedKeys::try_from(entries).unwrap_err();
    assert!(
        err.to_string().contains("key") && err.to_string().contains("missing"),
        "expected missing key error, got: {err}",
    );
}

// MATCH ARM
// ================================================================================================

/// Test enum to exercise match-arm decoding.
enum TestInput {
    WithKey(proto::primitives::SmtLeafEntry),
    Empty,
}

/// Wrapper for match-arm decode results.
#[derive(Debug)]
struct MatchResult {
    key: Option<Word>,
}

#[grpc_decode]
impl TryFrom<TestInput> for MatchResult {
    type Error = ConversionError;

    fn try_from(value: TestInput) -> Result<Self, Self::Error> {
        match value {
            TestInput::WithKey(entry) => {
                let key: Word = entry.key.decode()?;
                Ok(Self { key: Some(key) })
            },
            TestInput::Empty => Ok(Self { key: None }),
        }
    }
}

#[test]
fn test_match_arm_decode() {
    let input = TestInput::WithKey(proto::primitives::SmtLeafEntry {
        key: Some(valid_digest()),
        value: None,
    });
    let result = MatchResult::try_from(input).unwrap();
    assert_eq!(result.key.unwrap()[0], Felt::new(1));
}

#[test]
fn test_match_arm_empty_variant() {
    let input = TestInput::Empty;
    let result = MatchResult::try_from(input).unwrap();
    assert!(result.key.is_none());
}

#[test]
fn test_match_arm_missing_field() {
    let input = TestInput::WithKey(proto::primitives::SmtLeafEntry { key: None, value: None });
    let err = MatchResult::try_from(input).unwrap_err();
    assert!(
        err.to_string().contains("key") && err.to_string().contains("missing"),
        "expected missing key error, got: {err}",
    );
}
