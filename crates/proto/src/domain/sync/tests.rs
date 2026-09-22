use std::collections::HashMap;

use miden_protocol::Word;
use miden_protocol::note::Nullifier;

use crate::DecodeMessageExt;
use crate::generated::rpc::{self, SyncNullifiersResponse};

impl SyncNullifiersResponse {
    fn fixture(chain_tip: u32, checked: u32, spent: &[(u32, u32)]) -> Self {
        Self {
            pagination_info: Some(rpc::PaginationInfo { chain_tip, block_num: checked }),
            nullifiers: spent
                .iter()
                .map(|&(id, block_num)| rpc::sync_nullifiers_response::NullifierUpdate {
                    nullifier: Some(Word::from([id, 0, 0, 0]).into()),
                    block_num,
                })
                .collect(),
        }
    }
}

#[test]
fn sync_nullifiers_preserves_spend_blocks_and_partial_page_boundary() {
    let response = SyncNullifiersResponse::fixture(20, 12, &[(1, 12), (2, 4)])
        .decode_and_verify()
        .unwrap();

    assert_eq!(response.pagination_info.chain_tip.as_u32(), 20);
    assert_eq!(response.pagination_info.block_num.as_u32(), 12);
    assert_eq!(
        response.nullifiers,
        HashMap::from([
            (Nullifier::from_raw(Word::from([1_u32, 0, 0, 0])), 12.into()),
            (Nullifier::from_raw(Word::from([2_u32, 0, 0, 0])), 4.into()),
        ])
    );
}

#[test]
fn sync_nullifiers_accepts_empty_pages() {
    for (chain_tip, checked) in [(0, 0), (20, 12), (20, 20)] {
        let response = SyncNullifiersResponse::fixture(chain_tip, checked, &[])
            .decode_and_verify()
            .unwrap();
        assert!(response.nullifiers.is_empty());
        assert_eq!(response.pagination_info.block_num.as_u32(), checked);
    }
}

#[test]
fn sync_nullifiers_rejects_pagination_beyond_chain_tip() {
    let error = SyncNullifiersResponse::fixture(20, 21, &[]).decode_and_verify().unwrap_err();
    assert!(error.to_string().contains("pagination_info.block_num"), "{error}");
}

#[test]
fn sync_nullifiers_rejects_spends_beyond_last_checked_block() {
    let error = SyncNullifiersResponse::fixture(20, 12, &[(1, 13)])
        .decode_and_verify()
        .unwrap_err();
    assert!(error.to_string().contains("nullifiers[0].block_num"), "{error}");
}

#[test]
fn sync_nullifiers_rejects_duplicate_spends() {
    for second_block in [4, 5] {
        let error = SyncNullifiersResponse::fixture(20, 12, &[(1, 4), (1, second_block)])
            .decode_and_verify()
            .unwrap_err();
        assert!(error.to_string().contains("duplicate nullifier"), "{error}");
        assert!(error.to_string().contains("nullifiers[1].nullifier"), "{error}");
    }
}

#[test]
fn sync_nullifiers_rejects_missing_fields() {
    let mut missing_pagination = SyncNullifiersResponse::fixture(20, 12, &[]);
    missing_pagination.pagination_info = None;
    let error = missing_pagination.decode_and_verify().unwrap_err();
    assert!(error.to_string().contains("pagination_info"), "{error}");

    let mut missing_nullifier = SyncNullifiersResponse::fixture(20, 12, &[(1, 4)]);
    missing_nullifier.nullifiers[0].nullifier = None;
    let error = missing_nullifier.decode_and_verify().unwrap_err();
    assert!(error.to_string().contains("nullifiers[0].nullifier"), "{error}");
}

#[test]
fn sync_nullifiers_rejects_malformed_nullifiers() {
    let mut response = SyncNullifiersResponse::fixture(20, 12, &[(1, 4)]);
    response.nullifiers[0].nullifier.as_mut().unwrap().encoded = vec![0xff; 32];
    let error = response.decode_and_verify().unwrap_err();
    assert!(error.to_string().contains("nullifiers[0].nullifier"), "{error}");
}
