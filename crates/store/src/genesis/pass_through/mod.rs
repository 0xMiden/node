use anyhow::Context;
use miden_protocol::ONE;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountType};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;

const PASS_THROUGH_ACCOUNT_INIT_SEED: [u8; 32] = *b"miden-pass-through-account-seed!";

const PASS_THROUGH_AUTH_COMPONENT_PATH: &str = "miden_node::account::auth::pass_through";
const PASS_THROUGH_AUTH_COMPONENT_SOURCE: &str = include_str!("auth.masm");

/// The module path of the pass-through sweep component.
pub const PASS_THROUGH_SWEEP_COMPONENT_PATH: &str = "miden_node::account::pass_through::sweep";
const PASS_THROUGH_SWEEP_COMPONENT_SOURCE: &str = include_str!("sweep.masm");

/// Builds the public pass-through account that each genesis state contains.
///
/// The account has a stable ID because it uses a fixed seed. Its authentication procedure rejects
/// every state change. The account has no secret key.
pub fn build_pass_through_account() -> anyhow::Result<Account> {
    let auth_component = compile_component(
        PASS_THROUGH_AUTH_COMPONENT_PATH,
        PASS_THROUGH_AUTH_COMPONENT_SOURCE,
        "Pass-through authentication component",
    )?;
    let sweep_component = compile_component(
        PASS_THROUGH_SWEEP_COMPONENT_PATH,
        PASS_THROUGH_SWEEP_COMPONENT_SOURCE,
        "Pass-through asset sweep component",
    )?;

    let mut account = AccountBuilder::new(PASS_THROUGH_ACCOUNT_INIT_SEED)
        .account_type(AccountType::Public)
        .with_component(auth_component)
        .with_component(BasicWallet)
        .with_component(sweep_component)
        .build()?;

    // The genesis block deploys the account without a transaction.
    account.set_nonce(ONE)?;

    Ok(account)
}

/// Compiles the component that moves complete asset balances into an output note.
///
/// Transaction scripts must link this code dynamically before they call the sweep procedure.
pub fn pass_through_sweep_component_code() -> anyhow::Result<AccountComponentCode> {
    compile_component_code(PASS_THROUGH_SWEEP_COMPONENT_PATH, PASS_THROUGH_SWEEP_COMPONENT_SOURCE)
}

fn compile_component(
    path: &'static str,
    source: &'static str,
    description: &'static str,
) -> anyhow::Result<AccountComponent> {
    let code = compile_component_code(path, source)?;
    let metadata = AccountComponentMetadata::new(path).with_description(description);
    Ok(AccountComponent::new(code, vec![], metadata)?)
}

fn compile_component_code(
    path: &'static str,
    source: &'static str,
) -> anyhow::Result<AccountComponentCode> {
    CodeBuilder::default()
        .compile_component_code(path, source)
        .with_context(|| format!("failed to compile account component {path}"))
}

#[cfg(test)]
mod tests {
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
    use miden_testing::MockChain;

    use super::*;

    #[test]
    fn pass_through_account_is_stable_and_empty() -> anyhow::Result<()> {
        let account = build_pass_through_account()?;
        let rebuilt = build_pass_through_account()?;

        assert_eq!(account.id(), rebuilt.id());
        assert!(account.is_public());
        assert_eq!(account.nonce(), ONE);
        assert!(account.vault().is_empty());
        assert_eq!(account.storage().num_slots(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn pass_through_account_rejects_state_changes() -> anyhow::Result<()> {
        let mut builder = MockChain::builder();
        let account = build_pass_through_account()?;
        builder.add_account(account.clone())?;

        let note = builder.add_p2id_note(
            ACCOUNT_ID_SENDER.try_into()?,
            account.id(),
            &[FungibleAsset::mock(10)],
            NoteType::Public,
        )?;
        let mock_chain = builder.build()?;

        let result = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(note.id())
            .build()?
            .execute()
            .await;

        let error = result.expect_err("the pass-through account must reject a state change");
        assert!(error.to_string().contains("pass-through account must not change its state"));

        Ok(())
    }
}
