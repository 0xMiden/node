//! Prefunding the distributor: the faucet's recorded supply lands in its vault and it takes the
//! genesis form; anything that is not a fresh public wallet with a key is refused.

mod common;

use assert_matches::assert_matches;
use miden_objects::account_file::AccountFile;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{AccountBuilder, AccountType};
use miden_protocol::asset::AssetId;
use miden_protocol::{Felt, ONE};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::wallets::BasicWallet;
use xusdc_genesis::accounts::{prefund_distributor, PrefundError};

use crate::common::{fresh_distributor, genesis_faucet, Fixture, DISTRIBUTOR_SEED, TOKEN_SUPPLY};

/// The prefunded distributor keeps its id and keys, holds the faucet's whole recorded supply,
/// and is in genesis form (nonce one, no seed).
#[test]
fn prefund_gives_the_recorded_supply_and_promotes_to_genesis_form() {
    let faucet = genesis_faucet();
    let distributor = fresh_distributor();
    let prefunded = prefund_distributor(&faucet, &distributor).expect("the prefund must succeed");

    assert_eq!(
        prefunded.account().id(),
        distributor.account().id(),
        "the id is unchanged"
    );
    assert_eq!(
        prefunded.account().nonce(),
        ONE,
        "a genesis account carries nonce one"
    );
    assert!(
        prefunded.account().seed().is_none(),
        "a genesis account carries no seed"
    );
    assert_eq!(
        prefunded.auth_secret_keys(),
        distributor.auth_secret_keys(),
        "the keys are kept",
    );
    let recorded = FungibleFaucet::try_from(&faucet)
        .expect("the genesis faucet is a fungible faucet")
        .token_supply();
    assert_eq!(
        recorded.as_u64(),
        TOKEN_SUPPLY,
        "the fixture records the dev supply"
    );
    assert_eq!(
        prefunded
            .account()
            .vault()
            .get_balance(AssetId::new_fungible(faucet.id()))
            .expect("the balance is readable"),
        recorded,
        "the distributor must hold exactly the supply the faucet records as issued",
    );
}

/// A private wallet is refused: the funding service requires a public account.
#[test]
fn prefund_refuses_a_private_distributor() {
    let key = AuthSecretKey::new_ecdsa_k256_keccak();
    let account = AccountBuilder::new(DISTRIBUTOR_SEED)
        .account_type(AccountType::Private)
        .with_component(AuthSingleSig::from_public_key(key.public_key()))
        .with_component(BasicWallet)
        .build()
        .expect("the private wallet must build");
    let private = AccountFile::new(account, vec![key]);

    let err = prefund_distributor(&genesis_faucet(), &private)
        .expect_err("a private distributor must be refused");
    assert_matches!(err, PrefundError::DistributorNotPublic(id) if id == private.account().id());
}

/// A prefunded file fed back in is refused: prefund runs once per distributor.
#[test]
fn prefund_refuses_an_already_prefunded_distributor() {
    let faucet = genesis_faucet();
    let prefunded =
        prefund_distributor(&faucet, &fresh_distributor()).expect("the prefund must succeed");

    let err = prefund_distributor(&faucet, &prefunded)
        .expect_err("a second prefund of the same distributor must be refused");
    assert_matches!(
        err,
        PrefundError::DistributorNotFresh { id, nonce }
            if id == prefunded.account().id() && nonce == Felt::ONE
    );
}

/// A distributor file without a signing key is refused: nothing could ever spend the funds.
#[test]
fn prefund_refuses_a_distributor_without_a_key() {
    let keyless = AccountFile::new(fresh_distributor().into_parts().0, Vec::new());

    let err = prefund_distributor(&genesis_faucet(), &keyless)
        .expect_err("a keyless distributor must be refused");
    assert_matches!(err, PrefundError::DistributorHasNoSigningKey(id) if id == keyless.account().id());
}

/// A faucet recording no supply has nothing to distribute.
#[test]
fn prefund_refuses_a_faucet_with_no_supply() {
    let mut fixture = Fixture::new();
    fixture.json["faucet"]["token_supply"] = serde_json::Value::from(0u64);
    let faucet = xusdc_genesis::accounts::build_faucet(&fixture.config())
        .expect("a zero-supply faucet builds");

    let err = prefund_distributor(&faucet, &fresh_distributor())
        .expect_err("a zero supply must be refused");
    assert_matches!(err, PrefundError::NothingToDistribute);
}

/// A faucet input that is not a fungible faucet (here: a wallet) is refused.
#[test]
fn prefund_refuses_a_non_faucet_as_the_faucet() {
    let wallet = fresh_distributor().into_parts().0;

    let err = prefund_distributor(&wallet, &fresh_distributor())
        .expect_err("a wallet passed as the faucet must be refused");
    assert_matches!(err, PrefundError::NotAFungibleFaucet(_));
}
