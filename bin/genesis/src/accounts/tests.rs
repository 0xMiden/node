//! The genesis faucet's structural invariants, the generated distributor, prefunding it, and
//! recording consumed deposit nonces on the faucet.
//!
//! There is deliberately NO `MockChain` smoke test in this crate: a genesis account exists before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from the `.mac` file) belongs to `crates/xusdc-validation`.

use assert_matches::assert_matches;
use miden_protocol::account::{RoleSymbol, StorageMapKey};
use miden_protocol::{EMPTY_WORD, ONE};
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::account::fees::FeePolicyManager;
use miden_usdcx::account::xreserve::XReserveFaucetExtension;
use rstest::rstest;

use super::*;
use crate::test_utils::{
    DISTRIBUTOR_SEED,
    TOKEN_SUPPLY,
    fresh_distributor,
    genesis_faucet,
    used_nonces,
};

// FAUCET
// ================================================================================================

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN asset.
#[test]
fn the_faucet_is_a_native_fee_genesis_account() {
    let config = GenesisToolConfig::dev();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert_eq!(faucet.nonce(), Felt::ONE, "a genesis faucet carries nonce one");
    assert!(faucet.seed().is_none(), "a genesis faucet carries no seed");
    assert_eq!(
        faucet
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .expect("the faucet installs the fee-asset slot"),
        AssetId::new_fungible(faucet.id()).to_word(),
        "the fee-asset slot must be rebound to the faucet's own asset",
    );
}

/// The built faucet carries an enabled attester-allowlist row for every configured key.
#[test]
fn the_configured_attesters_are_allowlisted_in_storage() {
    let config = GenesisToolConfig::dev();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert!(
        !config.faucet.attesters.is_empty(),
        "the fixture must exercise a non-empty allowlist",
    );
    for key in &config.faucet.attesters {
        assert_eq!(
            faucet
                .storage()
                .get_map_item(
                    XReserveFaucetExtension::xreserve_attesters_slot(),
                    StorageMapKey::new(key.to_commitment()),
                )
                .expect("the faucet installs the attester allowlist slot"),
            Word::from([1u32, 0, 0, 0]),
            "the built faucet must carry the enabled row for every configured attester",
        );
    }
}

/// The built faucet records the configured token supply as issued: `prefund` hands exactly that
/// amount to the distributor.
#[test]
fn the_faucet_records_the_configured_supply() {
    let config = GenesisToolConfig::dev();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    let recorded =
        FungibleFaucet::try_from(&faucet).expect("the built faucet is a fungible faucet");
    assert_eq!(
        recorded.token_supply(),
        config.faucet.token_supply,
        "the configured supply must be the faucet's recorded issuance",
    );
}

/// A role configured with several holders parses and builds: every listed pauser is seeded as a
/// member of the built faucet's `DOM_PAUSER` role.
#[test]
fn a_multi_holder_role_builds_with_every_member_seeded() {
    let extra_pauser = AccountId::from_hex("0x2bb51b585b2a98916aebb827cc5899")
        .expect("the extra pauser id is valid hex");
    let mut config = GenesisToolConfig::dev();
    config.accounts.pausers.push(extra_pauser);
    let faucet = build_faucet(&config).expect("the two-pauser fixture must build");

    let role = RoleSymbol::new("DOM_PAUSER").expect("DOM_PAUSER is a valid role symbol");
    for pauser in &config.accounts.pausers {
        let key =
            Word::from([Felt::ZERO, Felt::from(&role), pauser.suffix(), pauser.prefix().as_felt()]);
        assert_eq!(
            faucet
                .storage()
                .get_map_item(
                    RoleBasedAccessControl::role_membership_slot(),
                    StorageMapKey::new(key),
                )
                .expect("the faucet installs the role-membership slot"),
            Word::from([1u32, 0, 0, 0]),
            "every configured pauser must be seeded as a DOM_PAUSER member",
        );
    }
    assert_eq!(config.accounts.pausers.len(), 2, "the fixture exercises two pausers");
}

/// An operational role with no holder still builds: the role is populated later through the
/// standard role-action note. Only `owner` is required.
#[test]
fn an_empty_operational_role_builds() {
    let mut config = GenesisToolConfig::dev();
    config.accounts.pausers.clear();
    config.accounts.unpausers.clear();
    build_faucet(&config).expect("empty operational roles must build");
}

// DISTRIBUTOR
// ================================================================================================

/// The wallet is public, undeployed (nonce zero, seed present, empty vault), and its single-sig
/// auth slot holds the commitment of the one key in the file.
fn assert_fresh_wallet_controlled_by_its_key(distributor: &AccountFile, scheme: AuthScheme) {
    let account = distributor.account();
    assert!(account.id().is_public(), "the distributor is a public account");
    assert_eq!(account.nonce(), ZERO, "a fresh distributor is undeployed");
    assert!(account.seed().is_some(), "an undeployed account carries its seed");
    assert!(account.vault().is_empty(), "a fresh distributor holds nothing");

    let [key] = distributor.auth_secret_keys() else {
        panic!("the file carries exactly one key");
    };
    assert_eq!(key.auth_scheme(), scheme, "the key is of the requested scheme");
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
#[case(AuthScheme::Falcon512Eidos)]
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

// PREFUND
// ================================================================================================

/// The prefunded distributor keeps its id and keys, holds the faucet's whole recorded supply, and
/// is in genesis form (nonce one, no seed).
#[test]
fn prefund_gives_the_recorded_supply_and_promotes_to_genesis_form() {
    let faucet = genesis_faucet();
    let distributor = fresh_distributor();
    let prefunded = prefund_distributor(&faucet, &distributor).expect("the prefund must succeed");

    assert_eq!(prefunded.account().id(), distributor.account().id(), "the id is unchanged");
    assert_eq!(prefunded.account().nonce(), ONE, "a genesis account carries nonce one");
    assert!(prefunded.account().seed().is_none(), "a genesis account carries no seed");
    assert_eq!(
        prefunded.auth_secret_keys(),
        distributor.auth_secret_keys(),
        "the keys are kept",
    );
    let recorded = FungibleFaucet::try_from(&faucet)
        .expect("the genesis faucet is a fungible faucet")
        .token_supply();
    assert_eq!(recorded.as_u64(), TOKEN_SUPPLY, "the fixture records the dev supply");
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
    let mut config = GenesisToolConfig::dev();
    config.faucet.token_supply = AssetAmount::ZERO;
    let faucet = build_faucet(&config).expect("a zero-supply faucet builds");

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

// RECORD NONCES
// ================================================================================================

/// Every listed nonce carries the consumed marker afterwards, and nothing else about the faucet
/// changes: id, genesis form, recorded supply, and the fee-asset rebinding.
#[test]
fn record_nonces_marks_every_nonce_and_changes_nothing_else() {
    let faucet = genesis_faucet();
    let nonces = used_nonces();
    assert_eq!(nonces.len(), 2, "the fixture exercises several nonces");

    let recorded = record_nonces(&faucet, &nonces).expect("recording must succeed");

    for nonce in &nonces {
        assert_eq!(
            recorded
                .storage()
                .get_map_item(
                    XReserveFaucetExtension::used_nonces_slot(),
                    nonce.to_storage_map_key(),
                )
                .expect("the faucet installs the nonce registry slot"),
            Word::from([1u32, 0, 0, 0]),
            "every listed nonce must be recorded as consumed",
        );
    }
    assert_eq!(recorded.id(), faucet.id(), "the id is unchanged");
    assert_eq!(recorded.nonce(), ONE, "the faucet stays at nonce one");
    assert!(recorded.seed().is_none(), "the faucet stays seedless");
    assert_eq!(
        FungibleFaucet::try_from(&recorded)
            .expect("still a fungible faucet")
            .token_supply()
            .as_u64(),
        TOKEN_SUPPLY,
        "the recorded supply is untouched",
    );
    assert_eq!(
        recorded
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .expect("the faucet installs the fee-asset slot"),
        AssetId::new_fungible(recorded.id()).to_word(),
        "the fee-asset rebinding is untouched",
    );
    let unlisted = DepositNonce::new([0x77; 32]);
    assert_eq!(
        recorded
            .storage()
            .get_map_item(
                XReserveFaucetExtension::used_nonces_slot(),
                unlisted.to_storage_map_key(),
            )
            .expect("the registry slot exists"),
        EMPTY_WORD,
        "an unlisted nonce stays unconsumed",
    );
}
