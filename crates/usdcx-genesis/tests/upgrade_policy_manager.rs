//! Upgrading the genesis faucet to the token policy manager V2.

mod common;

use anyhow::{Context, Result};
use miden_protocol::account::Account;
use miden_protocol::asset::AssetCallbacks;
use miden_standards::account::policies::{TokenPolicyManager, TokenPolicyManagerV2};
use miden_usdcx_genesis::accounts::{record_nonces, upgrade_policy_manager};

use crate::common::{NoncesFixture, genesis_faucet};

/// The genesis faucet with the fixture nonces recorded, the `upgrade-policy-manager` input.
fn recorded_faucet() -> Result<Account> {
    let nonces = NoncesFixture::new().parse()?.used_nonces;
    Ok(record_nonces(&genesis_faucet(), &nonces)?)
}

/// The asset callbacks of the upgraded faucet invoke the V2 transfer callbacks of its code, and the
/// V1 callbacks are gone.
#[test]
fn upgraded_faucet_invokes_the_v2_transfer_callbacks() -> Result<()> {
    let upgraded = upgrade_policy_manager(&recorded_faucet()?)?;

    for (slot_name, v2_root, v1_root) in [
        (
            AssetCallbacks::on_before_asset_added_to_note_slot(),
            TokenPolicyManagerV2::invoke_send_policy_root(),
            TokenPolicyManager::invoke_send_policy_root(),
        ),
        (
            AssetCallbacks::on_before_asset_added_to_account_slot(),
            TokenPolicyManagerV2::invoke_receive_policy_root(),
            TokenPolicyManager::invoke_receive_policy_root(),
        ),
    ] {
        assert_eq!(upgraded.storage().get_item(slot_name)?, v2_root.as_word());
        assert!(upgraded.code().has_procedure(v2_root.as_word()));
        assert!(!upgraded.code().has_procedure(v1_root.as_word()));
    }
    Ok(())
}

/// The upgrade keeps the id, vault, nonce and every storage slot apart from the asset callbacks,
/// including the recorded deposit nonces and the fee-asset rebinding.
#[test]
fn upgrade_keeps_the_faucet_state() -> Result<()> {
    let faucet = recorded_faucet()?;
    let upgraded = upgrade_policy_manager(&faucet)?;

    assert_eq!(upgraded.id(), faucet.id());
    assert_eq!(upgraded.vault(), faucet.vault());
    assert_eq!(upgraded.nonce(), faucet.nonce());
    assert!(upgraded.seed().is_none());

    let callback_slots = [
        AssetCallbacks::on_before_asset_added_to_note_slot(),
        AssetCallbacks::on_before_asset_added_to_account_slot(),
    ];
    assert_eq!(upgraded.storage().num_slots(), faucet.storage().num_slots());
    for slot in faucet.storage().slots() {
        if callback_slots.contains(&slot.name()) {
            continue;
        }
        let upgraded_slot = upgraded
            .storage()
            .get(slot.name())
            .with_context(|| format!("the upgraded faucet misses the slot {}", slot.name()))?;
        assert_eq!(upgraded_slot, slot, "the slot {} must be unchanged", slot.name());
    }
    Ok(())
}

/// An upgraded faucet is not upgraded a second time.
#[test]
fn upgrade_rejects_an_upgraded_faucet() -> Result<()> {
    let upgraded = upgrade_policy_manager(&recorded_faucet()?)?;

    assert!(upgrade_policy_manager(&upgraded).is_err());
    Ok(())
}
