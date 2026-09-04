//! Tests exercising the administration endpoints end to end.

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{Request, StatusCode};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use golden_ehtdh1::wire::{from_wire_bytes, to_wire_bytes};
use golden_ehtdh1::{Ciphertext, Combiner, DecryptionShare};
use golden_halo2curves::golden_group::Secp256k1GoldenGroup;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::transaction::{TransactionId, TransactionInputs};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_testing::{Auth, MockChainBuilder};
use rand_chacha_03::ChaCha20Rng;
use rand_chacha_03::rand_core::SeedableRng;
use tower::ServiceExt;

use super::error::ApiError;
use super::get_transaction::get_validated_private_transaction;
use super::issue_decryption_share::{
    IssueDecryptionShareRequest,
    IssueDecryptionShareResponse,
    issue_decryption_share,
};
use super::list_transactions::{
    ListTransactionsQuery,
    ListValidatedPrivateTransactionsResponse,
    MAX_PAGE_LIMIT,
    MAX_RECORD_PAGE_LIMIT,
    list_validated_private_transactions,
};
use super::{ISSUE_SHARE_PATH, LIST_TRANSACTIONS_PATH, ValidatorAdminService, router};
use crate::db::{ValidatorDbReader, ValidatorDbWriter};
use crate::storage_key::tests::operator_keys;
use crate::{
    GoldenOperatorKey,
    PrivateRecordChainId,
    PrivateRecordCombiner,
    PrivateRecordContext,
    PrivateRecordError,
    PrivateRecordId,
    PrivateRecordSealer,
    PrivateRecordShareRequest,
    StoredPrivateRecord,
};

fn target_record(
    operator_key: &GoldenOperatorKey,
    transaction_id: TransactionId,
    seed: u8,
    plaintext: &[u8],
) -> StoredPrivateRecord {
    let signer = SigningKey::read_from_bytes(&[9; 32]).unwrap();
    let record_id = PrivateRecordId::new(transaction_id, &signer.public_key());
    let context = PrivateRecordContext::new(
        PrivateRecordChainId::new([7; 32]),
        operator_key.key_epoch(),
        transaction_id,
    );
    PrivateRecordSealer::from_operator_key(operator_key)
        .seal(&mut ChaCha20Rng::from_seed([seed; 32]), record_id, context, plaintext)
        .unwrap()
}

fn transaction_inputs() -> TransactionInputs {
    let mut builder = MockChainBuilder::new();
    let account = builder
        .add_existing_wallet(Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        })
        .unwrap();
    builder.build().unwrap().get_transaction_inputs(&account, &[], &[]).unwrap()
}

async fn test_database() -> (tempfile::TempDir, ValidatorDbWriter, ValidatorDbReader) {
    let directory = tempfile::tempdir().unwrap();
    let writer = crate::db::setup(directory.path().join("validator.sqlite3")).await.unwrap();
    let reader = writer.reader();
    (directory, writer, reader)
}

fn share_request(record: &StoredPrivateRecord) -> IssueDecryptionShareRequest {
    IssueDecryptionShareRequest {
        ciphertext: hex::encode(record.encrypted_record_key()),
        decryption_context: hex::encode(record.context().to_bytes()),
    }
}

async fn issue(
    service: &ValidatorAdminService,
    request: IssueDecryptionShareRequest,
) -> Result<IssueDecryptionShareResponse, ApiError> {
    issue_decryption_share(State(service.clone()), Json(request))
        .await
        .map(|Json(response)| response)
}

async fn list(
    service: &ValidatorAdminService,
    query: ListTransactionsQuery,
) -> Result<ListValidatedPrivateTransactionsResponse, ApiError> {
    list_validated_private_transactions(State(service.clone()), Query(query))
        .await
        .map(|Json(response)| response)
}

/// Commits `transactions`, in that order, in a signed block at `block_num`. Only committed
/// transactions are listed, so listing tests have to place their records in a block.
async fn commit(writer: &ValidatorDbWriter, block_num: u32, transactions: &[TransactionId]) {
    writer
        .insert_signed_block(
            BlockHeader::mock(block_num, None, None, &[], Word::empty()),
            transactions.to_vec(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn listed_record_drives_threshold_recovery() {
    let mut keys = operator_keys();
    let record_owner = keys.pop().unwrap();
    let second = keys.pop().unwrap();
    let first = keys.pop().unwrap();
    let public_key_set = record_owner.public_key_set().clone();
    let setup_context = record_owner.setup_context().clone();
    let (_directory, writer, reader) = test_database().await;
    let first_service = ValidatorAdminService::new(first, reader.clone());
    let second_service = ValidatorAdminService::new(second, reader);
    let inputs = transaction_inputs();
    let transaction_id = TransactionId::from_raw(Word::from([8u32, 7, 6, 5]));
    let record = target_record(&record_owner, transaction_id, 10, &inputs.to_bytes());
    writer.insert_validated_private_transaction(record.clone()).await.unwrap();
    commit(&writer, 4, &[transaction_id]).await;

    let response = list(
        &first_service,
        ListTransactionsQuery {
            include_records: true,
            ..ListTransactionsQuery::default()
        },
    )
    .await
    .unwrap();
    let [listed] = response.transactions.as_slice() else {
        panic!("expected one listed transaction");
    };
    assert_eq!(listed.transaction_id, hex::encode(transaction_id.to_bytes()));
    assert_eq!((listed.block_num, listed.block_tx_index), (4, 0));
    assert_eq!(listed.key_epoch, hex::encode(record.context().key_epoch().as_bytes()));
    assert_eq!(listed.setup_context_id, hex::encode(record.setup_context_id()));
    let payload = listed.record.as_ref().expect("include_records must attach the record");
    assert_eq!(payload.final_ciphertext, hex::encode(record.encrypted_record()));
    assert_eq!(payload.cipher_nonce, hex::encode(record.nonce()));
    assert_eq!(payload.encrypted_record_key, hex::encode(record.encrypted_record_key()));
    assert_eq!(payload.decryption_context, hex::encode(record.context().to_bytes()));

    let request = share_request(&record);
    let share_bytes = [
        issue(&first_service, request.clone()).await.unwrap().decryption_share,
        issue(&second_service, request).await.unwrap().decryption_share,
    ];
    let ciphertext: Ciphertext<Secp256k1GoldenGroup> =
        from_wire_bytes(record.encrypted_record_key()).unwrap();
    let shares = share_bytes
        .iter()
        .map(|share| {
            let bytes = hex::decode(share).unwrap();
            from_wire_bytes::<DecryptionShare<Secp256k1GoldenGroup>>(&bytes).unwrap()
        })
        .collect::<Vec<_>>();
    let context = record.context().to_bytes();
    let content_key = Combiner::new(public_key_set, setup_context)
        .unwrap()
        .combine_exact_with_associated_data(&ciphertext, &context, &context, &shares)
        .unwrap();
    let plaintext = XChaCha20Poly1305::new_from_slice(&content_key)
        .unwrap()
        .decrypt(
            &XNonce::from(*record.nonce()),
            Payload {
                msg: record.encrypted_record(),
                aad: &context,
            },
        )
        .unwrap();

    assert_eq!(TransactionInputs::read_from_bytes(&plaintext).unwrap(), inputs);
}

/// Metadata-only listing (the default) omits the sealed record payload entirely.
#[tokio::test]
async fn list_returns_metadata_only_by_default() {
    let mut keys = operator_keys();
    let (_directory, writer, reader) = test_database().await;
    let transaction_id = TransactionId::from_raw(Word::from([3u32, 0, 0, 0]));
    let record = target_record(&keys[0], transaction_id, 21, b"record");
    writer.insert_validated_private_transaction(record).await.unwrap();
    commit(&writer, 1, &[transaction_id]).await;

    let service = ValidatorAdminService::new(keys.remove(0), reader);
    let response = list(&service, ListTransactionsQuery::default()).await.unwrap();
    let [listed] = response.transactions.as_slice() else {
        panic!("expected one listed transaction");
    };
    assert_eq!(listed.transaction_id, hex::encode(transaction_id.to_bytes()));
    assert!(listed.record.is_none());
}

/// A validated transaction that is not in a signed block is not listed, but is still retrievable by
/// id.
#[tokio::test]
async fn list_omits_uncommitted_transactions() {
    let mut keys = operator_keys();
    let (_directory, writer, reader) = test_database().await;
    let transaction_id = TransactionId::from_raw(Word::from([4u32, 0, 0, 0]));
    let record = target_record(&keys[0], transaction_id, 23, b"record");
    writer.insert_validated_private_transaction(record).await.unwrap();
    let service = ValidatorAdminService::new(keys.remove(0), reader);

    let response = list(&service, ListTransactionsQuery::default()).await.unwrap();
    assert!(response.transactions.is_empty());
    assert_eq!(response.pagination.block_num, None);

    let Json(fetched) = get_validated_private_transaction(
        State(service),
        Path(hex::encode(transaction_id.to_bytes())),
    )
    .await
    .unwrap();
    assert_eq!(fetched.transaction_id, hex::encode(transaction_id.to_bytes()));
}

/// A paged sweep returns committed rows in committed order, honoring the row limit exactly, and
/// terminates with an empty page reporting no position. A block range restricts results to the rows
/// committed in range.
#[tokio::test]
async fn list_pages_in_committed_order_and_filters_by_block_range() {
    let mut keys = operator_keys();
    let (_directory, writer, reader) = test_database().await;
    let transaction_ids = (1u64..=5)
        .map(|i| TransactionId::from_raw(Word::try_from([i, i, i, i]).unwrap()))
        .collect::<Vec<_>>();
    for (seed, transaction_id) in (31u8..=35).zip(&transaction_ids) {
        let record = target_record(&keys[0], *transaction_id, seed, b"record");
        writer.insert_validated_private_transaction(record).await.unwrap();
    }
    // Blocks 1 and 2 include two transactions each; the fifth is never committed. Block 1 includes
    // a later insertion first, to prove committed order wins over insertion order.
    commit(&writer, 1, &[transaction_ids[3], transaction_ids[0]]).await;
    commit(&writer, 2, &[transaction_ids[1], transaction_ids[2]]).await;
    let service = ValidatorAdminService::new(keys.remove(0), reader);
    let expected_sweep = [
        (transaction_ids[3], 1, 0),
        (transaction_ids[0], 1, 1),
        (transaction_ids[1], 2, 0),
        (transaction_ids[2], 2, 1),
    ]
    .map(|(id, block_num, index)| (hex::encode(id.to_bytes()), block_num, index));

    // Sweep asking for a single row per page: each page returns exactly one row, and the next page
    // is the same request resumed one position past the row just reported.
    let mut swept = Vec::new();
    let mut block_from = None;
    let mut tx_index_from = None;
    loop {
        let response = list(
            &service,
            ListTransactionsQuery {
                block_from,
                tx_index_from,
                limit: Some(1),
                ..ListTransactionsQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.pagination.chain_tip, 2, "the tip is reported on every page");
        let (Some(last_block), Some(last_index)) =
            (response.pagination.block_num, response.pagination.block_tx_index)
        else {
            assert!(response.transactions.is_empty(), "a page with rows must report its position");
            break;
        };
        assert_eq!(response.transactions.len(), 1, "a page must honor the row limit");
        block_from = Some(last_block);
        tx_index_from = Some(last_index + 1);
        swept.extend(
            response
                .transactions
                .into_iter()
                .map(|item| (item.transaction_id, item.block_num, item.block_tx_index)),
        );
    }
    assert_eq!(swept, expected_sweep);

    // A block filter excludes block 1, and the never-committed transaction is absent regardless of
    // the filter.
    let response = list(
        &service,
        ListTransactionsQuery {
            block_from: Some(2),
            block_to: Some(9),
            ..ListTransactionsQuery::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        response
            .transactions
            .iter()
            .map(|item| item.transaction_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            hex::encode(transaction_ids[1].to_bytes()),
            hex::encode(transaction_ids[2].to_bytes()),
        ],
    );
}

#[tokio::test]
async fn list_rejects_invalid_parameters() {
    let mut keys = operator_keys();
    let (_directory, _writer, reader) = test_database().await;
    let service = ValidatorAdminService::new(keys.remove(0), reader);

    for query in [
        ListTransactionsQuery {
            limit: Some(0),
            ..ListTransactionsQuery::default()
        },
        ListTransactionsQuery {
            limit: Some(MAX_PAGE_LIMIT + 1),
            ..ListTransactionsQuery::default()
        },
        ListTransactionsQuery {
            limit: Some(MAX_RECORD_PAGE_LIMIT + 1),
            include_records: true,
            ..ListTransactionsQuery::default()
        },
        ListTransactionsQuery {
            block_from: Some(3),
            block_to: Some(2),
            ..ListTransactionsQuery::default()
        },
        ListTransactionsQuery {
            tx_index_from: Some(1),
            ..ListTransactionsQuery::default()
        },
    ] {
        let error = list(&service, query).await.unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn get_transaction_returns_the_full_record() {
    let mut keys = operator_keys();
    let (_directory, writer, reader) = test_database().await;
    let transaction_id = TransactionId::from_raw(Word::from([6u32, 6, 6, 6]));
    let record = target_record(&keys[0], transaction_id, 22, b"record");
    writer.insert_validated_private_transaction(record.clone()).await.unwrap();
    let service = ValidatorAdminService::new(keys.remove(0), reader);

    let Json(fetched) = get_validated_private_transaction(
        State(service.clone()),
        Path(hex::encode(transaction_id.to_bytes())),
    )
    .await
    .unwrap();
    assert_eq!(fetched.transaction_id, hex::encode(transaction_id.to_bytes()));
    assert_eq!(fetched.final_ciphertext, hex::encode(record.encrypted_record()));
    assert_eq!(fetched.cipher_nonce, hex::encode(record.nonce()));
    assert_eq!(fetched.encrypted_record_key, hex::encode(record.encrypted_record_key()));
    assert_eq!(fetched.decryption_context, hex::encode(record.context().to_bytes()));

    let unknown_id = TransactionId::from_raw(Word::from([9u32, 9, 9, 9]));
    let error = get_validated_private_transaction(
        State(service.clone()),
        Path(hex::encode(unknown_id.to_bytes())),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, StatusCode::NOT_FOUND);

    let error = get_validated_private_transaction(State(service), Path("not hex".to_owned()))
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn shares_for_different_ciphertexts_are_not_reusable() {
    let mut keys = operator_keys();
    let record_owner = keys.pop().unwrap();
    let second = ValidatorAdminService::new(keys.pop().unwrap(), test_database().await.2);
    let first = ValidatorAdminService::new(keys.pop().unwrap(), test_database().await.2);
    let transaction_id = TransactionId::from_raw(Word::from([1u32, 2, 3, 4]));
    let first_record = target_record(&record_owner, transaction_id, 2, b"same plaintext");
    let second_record = target_record(&record_owner, transaction_id, 3, b"same plaintext");
    assert_eq!(first_record.context(), second_record.context());
    assert_ne!(first_record.encrypted_record_key(), second_record.encrypted_record_key());

    let shares = [
        issue(&first, share_request(&first_record)).await.unwrap().decryption_share,
        issue(&second, share_request(&second_record)).await.unwrap().decryption_share,
    ]
    .map(|share| hex::decode(share).unwrap());
    let request = PrivateRecordShareRequest::for_record(&first_record);
    let result = PrivateRecordCombiner::from_operator_key(&record_owner).unwrap().open(
        &request,
        &first_record,
        &shares,
    );

    assert!(matches!(result, Err(PrivateRecordError::ShareCombination(_))));
}

#[tokio::test]
async fn invalid_share_requests_return_bad_request() {
    let mut keys = operator_keys();
    let record =
        target_record(&keys[0], TransactionId::from_raw(Word::from([1u32, 2, 3, 4])), 4, b"record");
    let context = record.context().to_bytes();
    let (_directory, _writer, reader) = test_database().await;

    let invalid_hex = IssueDecryptionShareRequest {
        ciphertext: "not hex".to_owned(),
        decryption_context: hex::encode(&context),
    };
    let error = issue(&ValidatorAdminService::new(keys.remove(0), reader.clone()), invalid_hex)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);

    let mut short_rng = ChaCha20Rng::from_seed([5; 32]);
    let short_ciphertext = keys[0]
        .sealing_key()
        .seal_bytes_with_associated_data(&mut short_rng, &[0; 31], &context)
        .unwrap();
    let wrong_size = IssueDecryptionShareRequest {
        ciphertext: hex::encode(to_wire_bytes(&short_ciphertext)),
        decryption_context: hex::encode(context),
    };
    let error = issue(&ValidatorAdminService::new(keys.remove(0), reader.clone()), wrong_size)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);

    let wrong_context = IssueDecryptionShareRequest {
        ciphertext: hex::encode(record.encrypted_record_key()),
        decryption_context: hex::encode(b"wrong context"),
    };
    let error =
        issue(&ValidatorAdminService::new(operator_keys().remove(0), reader), wrong_context)
            .await
            .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn router_exposes_only_the_json_admin_routes() {
    let (_directory, _writer, reader) = test_database().await;
    let app = router(operator_keys().remove(0), reader);

    let response = app
        .clone()
        .oneshot(Request::get(LIST_TRANSACTIONS_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json",);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        body.as_ref(),
        br#"{"transactions":[],"pagination":{"chain_tip":0,"block_num":null,"block_tx_index":null}}"#
    );

    let response = app
        .clone()
        .oneshot(
            Request::get(format!("{LIST_TRANSACTIONS_PATH}/{}", hex::encode([1u8; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers().get("content-type").unwrap(), "application/json",);

    let response = app
        .clone()
        .oneshot(
            Request::post(ISSUE_SHARE_PATH)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ciphertext":"not hex","decryption_context":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app.oneshot(Request::get("/").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
