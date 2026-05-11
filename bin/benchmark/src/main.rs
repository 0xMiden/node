//! Runs benchmarks

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use miden_node_proto::clients::{Builder, RpcClient};
use miden_node_proto::generated::rpc::BlockHeaderByNumberRequest;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountId,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::{Asset, FungibleAsset, TokenSymbol};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::crypto::dsa::falcon512_poseidon2::{PublicKey, SecretKey};
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::Note;
use miden_protocol::transaction::{
    InputNoteCommitment,
    OutputNote,
    ProvenTransaction,
    PublicOutputNote,
    TxAccountUpdate,
};
use miden_protocol::vm::ExecutionProof;
use miden_protocol::{Felt, ONE, Word};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::faucets::{BasicFungibleFaucet, TokenMetadata};
use miden_standards::account::metadata::{FungibleTokenMetadata, TokenName};
use miden_standards::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::P2idNote;
use rand::Rng;
use url::Url;

const TOTAL_WALLETS: u64 = 1_000_000;

// COMMANDS
// ================================================================================================

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    CreateProofs,
    RunBenchmark,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    cli.run().await;
}

impl Cli {
    async fn run(self) {
        match self.command {
            Command::CreateProofs => self.create_proofs().await,
            Command::RunBenchmark => self.run_benchmark(),
        }
    }

    async fn create_proofs(self) {
        let url = Url::parse("https://rpc.devnet.miden.io").unwrap();
        let mut rpc_client =
            create_genesis_aware_rpc_client(&url, Duration::from_secs(10)).await.unwrap();

        // We need to:
        // 1. Create 1 faucet
        let mut faucet = create_faucet();

        // 2. Create N wallets
        let mut wallets = vec![];

        // share random coin seed and key pair for all accounts to avoid key generation overhead
        let coin_seed: [u64; 4] = rand::rng().random();
        let rng = Arc::new(Mutex::new(RandomCoin::new(coin_seed.map(Felt::new).into())));
        let key_pair = {
            let mut rng = rng.lock().unwrap();
            SecretKey::with_rng(&mut *rng)
        };

        for index in 0..TOTAL_WALLETS {
            let wallet = create_account(key_pair.public_key(), index, AccountStorageMode::Public);
            wallets.push(wallet);
        }

        // 3. Create 1 mint tx per wallet
        let block_header_from_rpc = rpc_client
            .get_block_header_by_number(get_genesis_header_request())
            .await
            .unwrap()
            .into_inner()
            .block_header;
        let genesis_block_header: BlockHeader = block_header_from_rpc.unwrap().try_into().unwrap();

        let mut mint_output_notes = vec![];
        let mut mint_txs = vec![];

        let faucet_id = faucet.id();
        for index in 0..TOTAL_WALLETS {
            let note = {
                let mut rng = rng.lock().unwrap();
                create_mint_note(faucet_id.clone(), wallets[index as usize].id().clone(), &mut rng)
            };
            mint_output_notes.push(note.clone());

            let mint_tx = create_mint_tx(&genesis_block_header, &mut faucet, vec![note]);
            mint_txs.push(mint_tx);
        }
        // 4. Create 1 consume tx per mint
        let mut consume_txs = vec![];

        for index in 0..TOTAL_WALLETS {
            let tx = create_consume_tx(
                &genesis_block_header,
                &mut wallets[index as usize],
                mint_output_notes[index as usize].clone(),
            );

            consume_txs.push(tx);
        }

        // Save everything to files
    }

    fn run_benchmark(self) {
        println!("run_benchmark");
    }
}

/// Create an RPC client configured with the correct genesis metadata in the
/// `Accept` header so that write RPCs such as `SubmitProvenTransaction` are
/// accepted by the node.
pub async fn create_genesis_aware_rpc_client(
    rpc_url: &Url,
    timeout: Duration,
) -> Result<RpcClient> {
    // First, create a temporary client without genesis metadata to discover the
    // genesis block header and its commitment.
    let mut rpc: RpcClient = Builder::new(rpc_url.clone())
        .with_tls()
        .context("Failed to configure TLS for RPC client")?
        .with_timeout(timeout)
        .without_metadata_version()
        .without_metadata_genesis()
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to create RPC client for genesis discovery")?;

    let response = rpc
        .get_block_header_by_number(get_genesis_header_request())
        .await
        .context("Failed to get genesis block header from RPC")?
        .into_inner();

    let genesis_block_header = response
        .block_header
        .ok_or_else(|| anyhow::anyhow!("No block header in response"))?;

    let genesis_header: BlockHeader =
        genesis_block_header.try_into().context("Failed to convert block header")?;

    let genesis_commitment = genesis_header.commitment();
    let genesis = genesis_commitment.to_hex();

    // Rebuild the client, this time including the required genesis metadata so that
    // write RPCs like SubmitProvenTransaction are accepted by the node.
    let rpc_client = Builder::new(rpc_url.clone())
        .with_tls()
        .context("Failed to configure TLS for RPC client")?
        .with_timeout(timeout)
        .without_metadata_version()
        .with_metadata_genesis(genesis)
        .without_otel_context_injection()
        .connect()
        .await
        .context("Failed to connect to RPC server with genesis metadata")?;

    Ok(rpc_client)
}

fn get_genesis_header_request() -> BlockHeaderByNumberRequest {
    BlockHeaderByNumberRequest {
        block_num: Some(BlockNumber::GENESIS.as_u32()),
        include_mmr_proof: None,
    }
}

/// Creates a new faucet account.
fn create_faucet() -> Account {
    let coin_seed: [u64; 4] = rand::rng().random();
    let mut rng = RandomCoin::new(coin_seed.map(Felt::new).into());
    let key_pair = SecretKey::with_rng(&mut rng);
    let init_seed = [0_u8; 32];

    let token_symbol = TokenSymbol::new("TEST").unwrap();
    let token_metadata = FungibleTokenMetadata::builder(
        TokenName::new("TEST").unwrap(),
        token_symbol,
        2,
        FungibleAsset::MAX_AMOUNT,
    )
    .build()
    .unwrap();
    AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Private)
        .with_component(token_metadata)
        .with_component(BasicFungibleFaucet)
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::AuthControlled,
            MintPolicyConfig::AllowAll,
            BurnPolicyConfig::AllowAll,
        ))
        .with_auth_component(AuthSingleSig::new(
            key_pair.public_key().into(),
            AuthScheme::Falcon512Poseidon2,
        ))
        .build()
        .unwrap()
}

/// Creates a new wallet account with a given public key.
fn create_account(public_key: PublicKey, index: u64, storage_mode: AccountStorageMode) -> Account {
    let init_seed: Vec<_> = index.to_be_bytes().into_iter().chain([0u8; 24]).collect();
    AccountBuilder::new(init_seed.try_into().unwrap())
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(storage_mode)
        .with_auth_component(AuthSingleSig::new(public_key.into(), AuthScheme::Falcon512Poseidon2))
        .with_component(BasicWallet)
        .build()
        .unwrap()
}

/// Creates a public P2ID note containing 10 tokens of the fungible asset associated with the
/// specified `faucet_id` and sent to the specified target account.
fn create_mint_note(faucet_id: AccountId, target_id: AccountId, rng: &mut RandomCoin) -> Note {
    let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 10).unwrap());
    P2idNote::create(
        faucet_id,
        target_id,
        vec![asset],
        miden_protocol::note::NoteType::Public,
        miden_protocol::note::NoteAttachment::default(),
        rng,
    )
    .expect("note creation failed")
}

/// Creates a transaction from the faucet that creates the given output notes.
/// Updates the faucet account to increase the issuance slot and it's nonce.
fn create_mint_tx(
    block_ref: &BlockHeader,
    faucet: &mut Account,
    output_notes: Vec<Note>,
) -> ProvenTransaction {
    let initial_account_hash = faucet.to_commitment();

    let metadata_slot_name = TokenMetadata::metadata_slot();
    let slot = faucet.storage().get_item(metadata_slot_name).unwrap();
    faucet
        .storage_mut()
        .set_item(metadata_slot_name, [slot[0] + Felt::new(10), slot[1], slot[2], slot[3]].into())
        .unwrap();

    faucet.increment_nonce(ONE).unwrap();

    let account_update = TxAccountUpdate::new(
        faucet.id(),
        initial_account_hash,
        faucet.to_commitment(),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();
    ProvenTransaction::new(
        account_update,
        Vec::<InputNoteCommitment>::new(),
        output_notes
            .into_iter()
            .map(|note| OutputNote::Public(PublicOutputNote::new(note).unwrap()))
            .collect::<Vec<OutputNote>>(),
        block_ref.block_num(),
        block_ref.commitment(),
        FungibleAsset::new(
            block_ref.fee_parameters().fee_faucet_id(),
            u64::from(block_ref.fee_parameters().verification_base_fee()),
        )
        .unwrap(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}

/// Creates a transaction from the wallet that will the given output note.
fn create_consume_tx(
    block_ref: &BlockHeader,
    wallet: &mut Account,
    input_note: Note,
) -> ProvenTransaction {
    let initial_account_hash = wallet.to_commitment();

    wallet.increment_nonce(ONE).unwrap();

    let account_update = TxAccountUpdate::new(
        wallet.id(),
        initial_account_hash,
        wallet.to_commitment(),
        Word::empty(),
        AccountUpdateDetails::Private,
    )
    .unwrap();

    let nullifier = input_note.nullifier();
    let header = input_note.header().clone();
    let input_note_commitment = InputNoteCommitment::from_parts_unchecked(nullifier, Some(header));

    ProvenTransaction::new(
        account_update,
        vec![input_note_commitment],
        Vec::<OutputNote>::new(),
        block_ref.block_num(),
        block_ref.commitment(),
        FungibleAsset::new(
            block_ref.fee_parameters().fee_faucet_id(),
            u64::from(block_ref.fee_parameters().verification_base_fee()),
        )
        .unwrap(),
        u32::MAX.into(),
        ExecutionProof::new_dummy(),
    )
    .unwrap()
}
