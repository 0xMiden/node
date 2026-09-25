use miden_protocol::block::BlockNumber;
use tonic::{Code, Status};

use super::*;

fn assert_client_error(status: &Status, detail: u8) {
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert_eq!(status.details(), &[detail], "{status}");
    assert!(!status.message().is_empty());
}

#[tokio::test]
async fn malformed_read_requests_return_method_specific_codes() {
    let (mut client, _, _store, _server) = start_rpc().await;

    let errors = [
        (
            client.get_account(proto::rpc::GetAccountRequest::default()).await.unwrap_err(),
            1,
        ),
        (
            client
                .get_notes_by_id(proto::rpc::GetNotesByIdRequest {
                    note_ids: vec![proto::note::NoteId::default()],
                })
                .await
                .unwrap_err(),
            1,
        ),
        (
            client
                .get_note_script_by_root(proto::rpc::GetNoteScriptByRootRequest::default())
                .await
                .unwrap_err(),
            1,
        ),
        (client.sync_notes(proto::rpc::SyncNotesRequest::default()).await.unwrap_err(), 3),
        (
            client
                .sync_nullifiers(proto::rpc::SyncNullifiersRequest::default())
                .await
                .unwrap_err(),
            3,
        ),
        (
            client
                .sync_account_vault(proto::rpc::SyncAccountVaultRequest::default())
                .await
                .unwrap_err(),
            2,
        ),
        (
            client
                .sync_account_storage_maps(proto::rpc::SyncAccountStorageMapsRequest::default())
                .await
                .unwrap_err(),
            2,
        ),
        (
            client
                .sync_transactions(proto::rpc::SyncTransactionsRequest::default())
                .await
                .unwrap_err(),
            2,
        ),
    ];

    for (error, detail) in errors {
        assert_client_error(&error, detail);
    }
}

#[tokio::test]
async fn reversed_sync_ranges_return_invalid_range_code() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let block_range = Some(proto::rpc::BlockRange { block_from: 1, block_to: 0 });
    let account_id = Some(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap().into());

    let errors = [
        client
            .sync_notes(proto::rpc::SyncNotesRequest { block_range, note_tags: vec![] })
            .await
            .unwrap_err(),
        client
            .sync_nullifiers(proto::rpc::SyncNullifiersRequest {
                block_range,
                prefix_len: 16,
                nullifiers: vec![],
            })
            .await
            .unwrap_err(),
        client
            .sync_account_vault(proto::rpc::SyncAccountVaultRequest { block_range, account_id })
            .await
            .unwrap_err(),
        client
            .sync_account_storage_maps(proto::rpc::SyncAccountStorageMapsRequest {
                block_range,
                account_id,
            })
            .await
            .unwrap_err(),
        client
            .sync_transactions(proto::rpc::SyncTransactionsRequest {
                block_range,
                account_ids: vec![],
            })
            .await
            .unwrap_err(),
    ];

    for error in errors {
        assert_client_error(&error, 1);
    }
}

#[tokio::test]
async fn private_account_sync_returns_method_specific_codes() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let block_range = Some(proto::rpc::BlockRange { block_from: 0, block_to: 0 });
    let account_id = Some(
        AccountId::dummy(
            [0; 15],
            AccountIdVersion::Version1,
            AccountType::Private,
            AssetCallbackFlag::Disabled,
        )
        .into(),
    );

    let vault = client
        .sync_account_vault(proto::rpc::SyncAccountVaultRequest { block_range, account_id })
        .await
        .unwrap_err();
    assert_client_error(&vault, 3);

    let storage = client
        .sync_account_storage_maps(proto::rpc::SyncAccountStorageMapsRequest {
            block_range,
            account_id,
        })
        .await
        .unwrap_err();
    assert_client_error(&storage, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn account_lookup_returns_distinct_error_codes() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let public_id = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    );
    let private_id = AccountId::dummy(
        [42; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    );

    for (account_id, block_num, detail) in [
        (public_id, None, 2),
        (private_id, None, 3),
        (public_id, Some(BlockNumber::from(1).into()), 4),
    ] {
        let error = client
            .get_account(proto::rpc::GetAccountRequest {
                account_id: Some(account_id.into()),
                block_num,
                details: Some(proto::rpc::get_account_request::AccountDetailRequest::default()),
            })
            .await
            .unwrap_err();
        assert_client_error(&error, detail);
    }
}

#[tokio::test]
async fn nullifier_prefix_errors_return_distinct_codes() {
    let (mut client, _, _store, _server) = start_rpc().await;

    for (prefix_len, nullifiers, detail) in [(15, vec![], 2), (16, vec![65536], 3)] {
        let error = client
            .sync_nullifiers(proto::rpc::SyncNullifiersRequest {
                block_range: Some(proto::rpc::BlockRange { block_from: 0, block_to: 0 }),
                prefix_len,
                nullifiers,
            })
            .await
            .unwrap_err();
        assert_client_error(&error, detail);
    }
}

#[tokio::test]
async fn chain_mmr_sync_returns_future_block_code() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let error = client
        .sync_chain_mmr(proto::rpc::SyncChainMmrRequest {
            current_client_block_height: 1,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_client_error(&error, 2);
}
