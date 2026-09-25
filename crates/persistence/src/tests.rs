use miden_objects::proto;
use miden_protocol::crypto::merkle::mmr::PartialMmr;
use prost::Message;

#[test]
fn mmr_storage_is_protobuf() {
    let mmr = PartialMmr::default();
    let bytes = crate::encode(&mmr);
    let message = proto::primitives::PartialMmr::decode(bytes.as_slice()).unwrap();
    assert_eq!(message.forest, 0);
    let restored: PartialMmr = crate::decode(&bytes).unwrap();
    assert_eq!(restored, mmr);
}

#[test]
fn invalid_account_is_rejected() {
    assert!(crate::decode::<miden_protocol::account::Account>(&[]).is_err());
}

#[test]
fn full_accounts_preserve_state() {
    use miden_protocol::account::Account;
    use miden_protocol::testing::add_component::AddComponent;
    use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
    let new = Account::builder([5; 32])
        .with_component(NoopAuthComponent)
        .with_component(AddComponent)
        .build()
        .unwrap();
    let existing = Account::new_existing(
        new.id(),
        miden_protocol::asset::AssetVault::mock(),
        miden_protocol::account::AccountStorage::mock(),
        miden_protocol::account::AccountCode::mock(),
        miden_protocol::Felt::ONE,
    );
    for account in [new, existing] {
        let restored: Account = crate::decode(&crate::encode(&account)).unwrap();
        assert_eq!(restored, account);
    }
}

#[test]
fn tracked_mmr_remains_updatable() {
    use miden_protocol::Word;
    let mut mmr = PartialMmr::default();
    for i in 0..7 {
        mmr.add(Word::from([i, 0, 0, 0_u32]), i % 2 == 0).unwrap();
    }
    let mut restored: PartialMmr = crate::decode(&crate::encode(&mmr)).unwrap();
    assert_eq!(restored, mmr);
    let leaf = Word::from([8, 0, 0, 0_u32]);
    mmr.add(leaf, true).unwrap();
    restored.add(leaf, true).unwrap();
    assert_eq!(restored, mmr);
    for i in [0, 2, 4, 6, 7] {
        assert_eq!(restored.open(i).unwrap(), mmr.open(i).unwrap());
    }
}

#[test]
fn malformed_and_duplicate_mmr_leaves_are_rejected() {
    use miden_protocol::Word;
    assert!(crate::decode::<PartialMmr>(&[0xff]).is_err());
    let mut mmr = PartialMmr::default();
    mmr.add(Word::empty(), true).unwrap();
    let mut message = proto::primitives::PartialMmr::from(&mmr);
    message.tracked_leaves.push(message.tracked_leaves[0].clone());
    assert!(crate::decode::<PartialMmr>(&message.encode_to_vec()).is_err());
}

#[test]
fn unknown_fields_are_accepted() {
    let mut bytes = crate::encode(&PartialMmr::default());
    bytes.extend_from_slice(&[0xa0, 0x06, 0x01]);
    assert_eq!(crate::decode::<PartialMmr>(&bytes).unwrap(), PartialMmr::default());
}

#[test]
fn empty_collections_roundtrip() {
    use miden_protocol::block::BlockSignatures;
    use miden_protocol::note::{NoteAssets, NoteHeader};
    let signatures = BlockSignatures::new(vec![]).unwrap();
    let restored: BlockSignatures = crate::decode(&crate::encode(&signatures)).unwrap();
    assert_eq!(restored, signatures);
    let assets = NoteAssets::new(vec![]).unwrap();
    let restored: NoteAssets = crate::decode(&crate::encode(&assets)).unwrap();
    assert_eq!(restored, assets);
    assert!(
        crate::decode::<Vec<NoteHeader>>(&crate::encode(&Vec::<NoteHeader>::new()))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn signature_collection_enforces_domain_limit() {
    use miden_protocol::block::{BlockSignatures, ValidatorConfig};
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::utils::serde::Deserializable;
    let signer = SigningKey::read_from_bytes(&[7; 32]).unwrap();
    let signature = signer.sign(miden_protocol::Word::empty());
    let message = crate::generated::BlockSignatures {
        signatures: vec![(&signature).into(); ValidatorConfig::MAX_VALIDATORS + 1],
    };
    assert!(crate::decode::<BlockSignatures>(&message.encode_to_vec()).is_err());
}

#[test]
fn empty_note_attachments_roundtrip() {
    use miden_protocol::note::NoteAttachments;
    let attachments = NoteAttachments::empty();
    assert_eq!(
        crate::decode::<NoteAttachments>(&crate::encode(&attachments)).unwrap(),
        attachments
    );
}
