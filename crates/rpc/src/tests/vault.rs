use miden_node_proto::DecodeMessageExt;
use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountStorageRequest,
    AccountVaultDetails,
    AccountVaultRequest,
    GetAccountRequest,
};
use miden_node_proto::generated::miden::node::v1::get_account_request::account_detail_request::{
    VaultAssetIds,
    VaultRequest,
};
use miden_node_store::GenesisState;
use miden_node_utils::fee::{test_fee_params, test_protocol_config};
use miden_protocol::asset::{NonFungibleAsset, NonFungibleAssetDetails};
use miden_protocol::block::BlockNumber;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::testing::random_secret_key::random_secret_key;

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn get_account_selects_assets_from_a_large_vault() {
    let faucet = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([7; 32]);
    let assets = (0..=AccountVaultDetails::MAX_RETURN_ENTRIES)
        .map(|i| {
            Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
                faucet,
                (i as u64).to_le_bytes().to_vec(),
            )))
        })
        .collect::<Vec<_>>();
    let absent =
        Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet, vec![255]))).id();
    let account = AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_component(NoopAuthComponent)
        .with_assets(assets.clone())
        .build_existing()
        .unwrap();
    let genesis = GenesisState::new(
        vec![account.clone()],
        test_fee_params(),
        1,
        ValidatorConfig::new(vec![random_secret_key().public_key()], 1).unwrap(),
        test_protocol_config(),
    )
    .into_block()
    .unwrap();
    let directory = new_tempdir();
    State::bootstrap(genesis, &directory).await.unwrap();
    let (state, _writer, _proof_writer) = State::for_tests(&directory).await;
    let keys = vec![assets[0].id(), absent];
    for vault_request in [
        AccountVaultRequest::All(Word::empty()),
        AccountVaultRequest::Assets(keys.clone()),
    ] {
        let full = matches!(vault_request, AccountVaultRequest::All(_));
        let response = state
            .view()
            .get_account(GetAccountRequest {
                account_id: account.id(),
                block_num: Some(BlockNumber::GENESIS),
                details: Some(AccountDetailRequest {
                    code_commitment: None,
                    vault_request,
                    storage_request: AccountStorageRequest::None,
                }),
            })
            .await
            .unwrap();
        let wire: proto::miden::node::v1::GetAccountResponse = response.into();
        let response = wire.decode_and_verify().unwrap();
        assert_eq!(response.block_num, BlockNumber::GENESIS);
        match response.details.unwrap().vault_details {
            AccountVaultDetails::LimitExceeded => assert!(full),
            AccountVaultDetails::Partial { asset_ids, vault } => {
                assert!(!full);
                assert_eq!(asset_ids, keys);
                assert_eq!(vault.root(), account.vault().root());
                assert_eq!(vault.assets().collect::<Vec<_>>(), vec![assets[0]]);
                for id in keys.iter().copied() {
                    assert_eq!(vault.open(id).unwrap(), account.vault().open(id));
                }
            },
            AccountVaultDetails::Assets(_) => panic!("large vault should not be returned in full"),
        }
    }
}

#[tokio::test]
async fn get_account_rejects_excessive_and_duplicate_vault_ids() {
    let (mut client, _, _store, _server) = start_rpc().await;
    let faucet = AccountIdBuilder::new()
        .account_type(AccountType::Public)
        .build_with_seed([7; 32]);
    let ids = (0..=QueryParamVaultAssetLimit::LIMIT)
        .map(|i| {
            Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
                faucet,
                (i as u64).to_le_bytes().to_vec(),
            )))
            .id()
        })
        .collect::<Vec<_>>();
    for (ids, code) in [
        (ids.clone(), tonic::Code::OutOfRange),
        (vec![ids[0], ids[0]], tonic::Code::InvalidArgument),
    ] {
        let error = client
            .get_account(proto::miden::node::v1::GetAccountRequest {
                account_id: Some(faucet.into()),
                block_num: None,
                details: Some(proto::miden::node::v1::get_account_request::AccountDetailRequest {
                    vault_request: Some(VaultRequest::AssetIds(VaultAssetIds {
                        asset_ids: ids.into_iter().map(Into::into).collect(),
                    })),
                    ..Default::default()
                }),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), code);
    }
}
