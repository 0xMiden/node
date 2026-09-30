//! The generated distributor: a fresh public basic wallet controlled by the key its file carries.

mod common;

use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::{Word, ZERO};
use miden_standards::account::auth::AuthSingleSig;
use rstest::rstest;
use xusdc_genesis::accounts::{new_distributor, new_distributor_with};

use crate::common::DISTRIBUTOR_SEED;

/// The wallet is public, undeployed (nonce zero, seed present, empty vault), and its single-sig
/// auth slot holds the commitment of the one key in the file.
fn assert_fresh_wallet_controlled_by_its_key(distributor: &AccountFile, scheme: AuthScheme) {
    let account = distributor.account();
    assert!(
        account.id().is_public(),
        "the distributor is a public account"
    );
    assert_eq!(account.nonce(), ZERO, "a fresh distributor is undeployed");
    assert!(
        account.seed().is_some(),
        "an undeployed account carries its seed"
    );
    assert!(
        account.vault().is_empty(),
        "a fresh distributor holds nothing"
    );

    let [key] = distributor.auth_secret_keys() else {
        panic!("the file carries exactly one key");
    };
    assert_eq!(
        key.auth_scheme(),
        scheme,
        "the key is of the requested scheme"
    );
    assert_eq!(
        account
            .storage()
            .get_item(AuthSingleSig::public_key_slot())
            .expect("the wallet installs the single-sig public key slot"),
        Word::from(key.public_key().to_commitment()),
        "the wallet must be controlled by the key its file carries",
    );
}

/// A distributor generated for either scheme is a fresh public wallet controlled by its key.
#[rstest]
#[case(AuthScheme::EcdsaK256Keccak)]
#[case(AuthScheme::Falcon512Poseidon2)]
fn new_distributor_is_a_fresh_wallet_controlled_by_its_key(#[case] scheme: AuthScheme) {
    let distributor = new_distributor(scheme).expect("the distributor must generate");
    assert_fresh_wallet_controlled_by_its_key(&distributor, scheme);

    let other = new_distributor(scheme).expect("a second distributor must generate");
    assert_ne!(
        other.account().id(),
        distributor.account().id(),
        "every generation draws a fresh key and seed",
    );
}

/// The same seed and key compose the same distributor.
#[test]
fn new_distributor_with_is_deterministic_in_its_inputs() {
    let key = AuthSecretKey::new_ecdsa_k256_keccak();
    let first =
        new_distributor_with(DISTRIBUTOR_SEED, key.clone()).expect("the distributor must compose");
    let second = new_distributor_with(DISTRIBUTOR_SEED, key).expect("the distributor must compose");
    assert_fresh_wallet_controlled_by_its_key(&first, AuthScheme::EcdsaK256Keccak);
    assert_eq!(first.account(), second.account());
}
