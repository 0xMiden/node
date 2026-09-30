//! Recording consumed deposit nonces on the genesis faucet.

mod common;

use miden_protocol::asset::AssetId;
use miden_protocol::{Word, EMPTY_WORD, ONE};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::fees::FeePolicyManager;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::xreserve::encoding::DepositNonce;
use xusdc_genesis::accounts::record_nonces;

use crate::common::{genesis_faucet, NoncesFixture, TOKEN_SUPPLY};

/// Every listed nonce carries the consumed marker afterwards, and nothing else about the faucet
/// changes: id, genesis form, recorded supply, and the fee-asset rebinding.
#[test]
fn record_nonces_marks_every_nonce_and_changes_nothing_else() {
    let faucet = genesis_faucet();
    let nonces = NoncesFixture::new()
        .parse()
        .expect("the nonces fixture parses")
        .used_nonces;
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
