//! Structural invariants of the built genesis faucet: nonce-one genesis form and the native-fee
//! rebinding.
//!
//! There is deliberately NO MockChain smoke test in this crate: a genesis account exists before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from the `.mac` file) belongs to `crates/xusdc-validation`.

mod common;

use miden_protocol::account::StorageMapKey;
use miden_protocol::asset::AssetId;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::FeePolicyManager;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_genesis::accounts::build_faucet;

use crate::common::Fixture;

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN
/// asset.
#[test]
fn the_faucet_is_a_native_fee_genesis_account() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert_eq!(
        faucet.nonce(),
        Felt::ONE,
        "a genesis faucet carries nonce one"
    );
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
    let fixture = Fixture::new();
    let config = fixture.config();
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

/// The built faucet records the configured token supply as issued: `prefund` hands exactly
/// that amount to the distributor.
#[test]
fn the_faucet_records_the_configured_supply() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    let recorded = miden_standards::account::faucets::FungibleFaucet::try_from(&faucet)
        .expect("the built faucet is a fungible faucet");
    assert_eq!(
        recorded.token_supply(),
        config.faucet.token_supply,
        "the configured supply must be the faucet's recorded issuance",
    );
}

/// A role configured with several holders parses and builds: every listed pauser is seeded as a
/// member of the built faucet's DOM_PAUSER role.
#[test]
fn a_multi_holder_role_builds_with_every_member_seeded() {
    use miden_protocol::account::{AccountId, RoleSymbol};

    let extra_pauser = "0x2bb51b585b2a98916aebb827cc5899";
    let mut fixture = Fixture::new();
    let existing = fixture.json["accounts"]["pausers"][0].clone();
    fixture.json["accounts"]["pausers"] = serde_json::Value::from(vec![
        existing
            .as_str()
            .expect("the fixture pauser is a string")
            .to_string(),
        extra_pauser.to_string(),
    ]);
    let config = fixture.config();
    let faucet = build_faucet(&config).expect("the two-pauser fixture must build");

    let role = RoleSymbol::new("DOM_PAUSER").expect("DOM_PAUSER is a valid role symbol");
    for pauser in &config.accounts.pausers {
        let key = Word::from([
            Felt::ZERO,
            Felt::from(&role),
            pauser.suffix(),
            pauser.prefix().as_felt(),
        ]);
        assert_eq!(
            faucet
                .storage()
                .get_map_item(
                    miden_standards::account::access::RoleBasedAccessControl::role_membership_slot(
                    ),
                    StorageMapKey::new(key),
                )
                .expect("the faucet installs the role-membership slot"),
            Word::from([1u32, 0, 0, 0]),
            "every configured pauser must be seeded as a DOM_PAUSER member",
        );
    }
    let _: AccountId = config.accounts.pausers[1];
}

/// An operational role configured with an empty list (or absent) still builds: the role is
/// populated later through the standard role-action note. Only `owner` is required.
#[test]
fn an_empty_operational_role_builds() {
    let mut fixture = Fixture::new();
    fixture.json["accounts"]["pausers"] = serde_json::Value::from(Vec::<String>::new());
    fixture.json["accounts"]
        .as_object_mut()
        .expect("the accounts section is an object")
        .remove("unpausers");
    build_faucet(&fixture.config()).expect("empty and absent operational roles must build");
}
