use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use miden_node_proto::DecodeMessageExt;
use miden_node_proto::clients::RpcClient;
use miden_node_proto::generated::miden::node::v1::{
    BlockRange,
    GetNotesByIdRequest,
    SyncNotesRequest,
    SyncNullifiersRequest,
};
use miden_node_tracing::{Level, enabled, miden_instrument, miden_span_record};
use miden_node_utils::limiter::{
    QueryParamLimiter,
    QueryParamNoteIdLimit,
    QueryParamNullifierPrefixLimit,
};
use miden_node_utils::usdcx_p2id::UsdcxP2Id;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{Note, NoteId, NoteTag, Nullifier};

use super::FundingWallet;
use crate::COMPONENT;

impl FundingWallet {
    /// Finds deposits in the given block range.
    pub(super) async fn scan_deposits(
        &self,
        rpc: &mut RpcClient,
        from: BlockNumber,
        tip: BlockNumber,
    ) -> Result<HashMap<Nullifier, UsdcxP2Id>> {
        let mut next_block = from;
        let mut deposits = HashMap::new();
        while next_block <= tip {
            let page =
                Self::sync_deposits(rpc, self.account_id(), self.fee_asset_id, next_block, tip)
                    .await?;
            deposits.extend(page.deposits.into_iter().map(|note| (note.nullifier(), note)));
            next_block = page.last_checked_block + 1;
        }
        Ok(deposits)
    }

    /// Returns one page of deposits and the last block checked in the given range.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.wallet.sync_deposits",
        level = "debug",
        fields(
            account.id = funder,
            block_range.from = from_block,
            block_range.to = to_block,
        ),
        err(level = "debug"),
    )]
    async fn sync_deposits(
        rpc: &mut RpcClient,
        funder: AccountId,
        fee_asset_id: AssetId,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> Result<SyncedDeposits> {
        let response = rpc
            .sync_notes(SyncNotesRequest {
                block_range: Some(BlockRange {
                    block_from: from_block.as_u32(),
                    block_to: to_block.as_u32(),
                }),
                note_tags: vec![NoteTag::with_account_target(funder).as_u32()],
            })
            .await
            .context("failed to synchronize notes")?
            .into_inner();

        let last_checked_block: BlockNumber = response
            .pagination_info
            .context("the sync_notes response did not include pagination information")?
            .block_num
            .into();
        anyhow::ensure!(
            (from_block..=to_block).contains(&last_checked_block),
            "the node answered a note scan from {from_block} to {to_block} with block {last_checked_block}",
        );

        let mut note_ids = Vec::new();
        for block in response.blocks {
            for record in block.notes {
                let proof = record
                    .inclusion_proof
                    .context("a note sync record did not include an inclusion proof")?;
                let note_id = proof
                    .note_id
                    .context("a note inclusion proof did not include a note ID")?
                    .decode_and_verify()
                    .context("failed to verify a synced note ID")?;
                note_ids.push(note_id);
            }
        }

        if enabled!(target: COMPONENT, Level::DEBUG) {
            miden_span_record!(note.count = note_ids.len(), block.number = last_checked_block);
        }
        let deposits: Vec<_> = Self::get_public_notes_by_id(rpc, &note_ids)
            .await?
            .into_iter()
            .filter_map(|note| UsdcxP2Id::from_note(note, fee_asset_id))
            .filter(|note| note.target() == funder && note.amount() > 0)
            .collect();

        if enabled!(target: COMPONENT, Level::DEBUG) {
            miden_span_record!(deposit.count = deposits.len());
        }
        Ok(SyncedDeposits { deposits, last_checked_block })
    }

    /// The notes among `note_ids` whose details the node stores.
    #[miden_instrument(
        target = COMPONENT,
        name = "funding.wallet.get_notes",
        level = "debug",
        fields(
            note.count = note_ids.len(),
        ),
        err(level = "debug"),
    )]
    async fn get_public_notes_by_id(rpc: &mut RpcClient, note_ids: &[NoteId]) -> Result<Vec<Note>> {
        let mut notes = Vec::new();

        // The node rejects a request which asks for more note IDs than it accepts, so the IDs are
        // requested in chunks of the limit it enforces.
        for chunk in note_ids.chunks(QueryParamNoteIdLimit::LIMIT) {
            let note_ids = chunk.iter().map(|note_id| note_id.as_word().into()).collect();

            let response = rpc
                .get_notes_by_id(GetNotesByIdRequest { note_ids })
                .await
                .context("failed to fetch notes from RPC")?
                .into_inner();

            for committed in response.notes {
                let Some(note) = committed.note else {
                    continue;
                };
                if note.note_details.is_none() {
                    continue;
                }

                let note = note.decode_and_verify().context("failed to verify a committed note")?;
                notes.push(note);
            }
        }

        Ok(notes)
    }
}

/// The result of one deposit synchronization.
struct SyncedDeposits {
    /// The matching deposits. These notes can already be spent.
    deposits: Vec<UsdcxP2Id>,
    /// The last block the node checked. The next scan starts after it.
    last_checked_block: BlockNumber,
}

/// Returns the requested nullifiers spent in the given block range.
#[miden_instrument(
    target = COMPONENT,
    name = "funding.wallet.spent_nullifiers",
    fields(
        nullifier.count = nullifiers.len(),
        block_range.to = tip,
    ),
    err,
)]
pub(super) async fn spent_nullifiers(
    rpc: &mut RpcClient,
    nullifiers: &[Nullifier],
    from: BlockNumber,
    tip: BlockNumber,
) -> Result<HashSet<Nullifier>> {
    let requested: HashSet<_> = nullifiers.iter().copied().collect();
    let mut prefixes: Vec<_> = nullifiers.iter().map(|n| u32::from(n.prefix())).collect();
    prefixes.sort_unstable();
    prefixes.dedup();
    let mut spent = HashSet::new();
    let mut pages = 0_usize;

    for chunk in prefixes.chunks(QueryParamNullifierPrefixLimit::LIMIT) {
        let mut start = from;
        while start <= tip {
            let response = rpc
                .sync_nullifiers(SyncNullifiersRequest {
                    block_range: Some(BlockRange {
                        block_from: start.as_u32(),
                        block_to: tip.as_u32(),
                    }),
                    prefix_len: 16,
                    nullifiers: chunk.to_vec(),
                })
                .await
                .context("failed to synchronize nullifiers")?
                .into_inner()
                .decode_and_verify()
                .context("failed to convert the nullifier sync response")?;

            pages += 1;
            let last_checked = response.pagination_info.block_num;
            anyhow::ensure!(
                (start..=tip).contains(&last_checked),
                "the node answered a nullifier scan from {start} to {tip} with block {last_checked}",
            );
            for nullifier in response.nullifiers.into_keys() {
                // Prefix matches can include nullifiers that were not requested.
                if requested.contains(&nullifier) {
                    spent.insert(nullifier);
                }
            }
            if last_checked == tip {
                break;
            }
            start = last_checked + 1;
        }
    }

    miden_span_record!(page.count = pages, nullifier.spent.count = spent.len());
    Ok(spent)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use miden_objects::account_file::AccountFile;
    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::asset::FungibleAsset;
    use miden_protocol::note::NoteType;
    use miden_standards::note::P2idNote;

    use super::*;
    use crate::node::tests::{TestChain, TestServer};

    fn wallet() -> FundingWallet {
        let faucet = TestChain::account_id();
        let (account, key) = crate::test_utils::genesis_style_wallet(faucet, 0, [9; 32]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.mac");
        AccountFile::new(account, vec![AuthSecretKey::Falcon512Poseidon2(key)])
            .write(&path)
            .unwrap();
        FundingWallet::load(&path, AssetId::new_fungible(faucet)).unwrap()
    }

    fn deposit(wallet: &FundingWallet, serial: u32, amount: u64) -> Note {
        P2idNote::builder()
            .sender(TestChain::account_id())
            .target(wallet.account_id())
            .asset(FungibleAsset::new(TestChain::account_id(), amount).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([serial; 4]))
            .build()
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn discovery_recovers_historical_deposits_and_continues_with_new_blocks() {
        let wallet = wallet();
        let first = deposit(&wallet, 1, 1_000);
        let second = deposit(&wallet, 2, 1_000);
        let third = deposit(&wallet, 3, 1_000);
        let mut chain = TestChain::new(12);
        chain.notes = vec![(3, first.clone()), (10, second.clone())];
        chain.unavailable = Some("GetNotesById");
        let server = TestServer::start(chain).await;

        assert!(
            wallet
                .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
                .await
                .is_err()
        );
        server.chain.lock().unwrap().unavailable = None;
        let recovered = wallet
            .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
            .await
            .unwrap();
        assert_eq!(
            recovered
                .into_values()
                .map(|deposit| (deposit.note().id(), deposit.into_note()))
                .collect::<HashMap<_, _>>(),
            HashMap::from([(first.id(), first), (second.id(), second)]),
        );

        {
            let mut chain = server.chain.lock().unwrap();
            chain.tip = 15;
            chain.notes.push((14, third.clone()));
        }
        let discovered = wallet
            .scan_deposits(&mut server.node.rpc_client(), 13.into(), 15.into())
            .await
            .unwrap();
        assert_eq!(
            discovered.into_values().map(UsdcxP2Id::into_note).collect::<Vec<_>>(),
            vec![third]
        );
    }
    /// Tag matches can include notes addressed to a different account.
    #[tokio::test]
    async fn discovery_filters_notes_by_the_wallet_account_id() {
        use miden_protocol::note::PartialNoteMetadata;

        let wallet = wallet();
        let funder = wallet.account_id();
        let faucet = TestChain::account_id();
        let (other, _) = crate::test_utils::genesis_style_wallet(faucet, 0, [5; 32]).unwrap();
        let note: Note = P2idNote::builder()
            .sender(funder)
            .target(other.id())
            .asset(FungibleAsset::new(faucet, 1_000).unwrap())
            .note_type(NoteType::Public)
            .serial_number(Word::from([5u32; 4]))
            .build()
            .unwrap()
            .into();
        let other_note = Note::new(
            note.assets().clone(),
            PartialNoteMetadata::new(funder, NoteType::Public)
                .with_tag(NoteTag::with_account_target(funder)),
            note.recipient().clone(),
        );
        let deposit = deposit(&wallet, 1, 1_000);
        let mut chain = TestChain::new(12);
        chain.notes = vec![(3, other_note), (3, deposit.clone())];
        let server = TestServer::start(chain).await;
        let notes = wallet
            .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
            .await
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[&deposit.nullifier()].note(), &deposit);
    }

    #[tokio::test]
    async fn discovery_skips_zero_amount_deposits() {
        let wallet = wallet();
        let zero = deposit(&wallet, 2, 0);
        let deposit = deposit(&wallet, 1, 1_000);
        let mut chain = TestChain::new(12);
        chain.notes = vec![(3, zero), (3, deposit.clone())];
        let server = TestServer::start(chain).await;
        let notes = wallet
            .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
            .await
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[&deposit.nullifier()].note(), &deposit);
    }

    #[tokio::test]
    async fn invalid_note_pagination_does_not_skip_deposits() {
        let wallet = wallet();
        let deposit = deposit(&wallet, 1, 1_000);
        let mut chain = TestChain::new(12);
        chain.notes = vec![(3, deposit.clone())];
        chain.invalid_checked = Some(13);
        let server = TestServer::start(chain).await;

        assert!(
            wallet
                .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
                .await
                .is_err()
        );
        server.chain.lock().unwrap().invalid_checked = None;
        assert_eq!(
            wallet
                .scan_deposits(&mut server.node.rpc_client(), BlockNumber::GENESIS, 12.into())
                .await
                .unwrap()
                .into_values()
                .map(UsdcxP2Id::into_note)
                .collect::<Vec<_>>(),
            vec![deposit]
        );
    }
    // DEPOSIT DISCOVERY
    // ================================================================================================

    #[tokio::test]
    async fn a_prefix_collision_does_not_mark_an_unspent_deposit_as_spent() {
        let deposit = TestChain::deposit(1);
        let mut word = deposit.nullifier().as_word();
        word[0] += miden_protocol::Felt::ONE;
        let other = Nullifier::from_raw(word);
        let mut chain = TestChain::new(12);
        chain.spent = vec![(10, other)];
        let server = TestServer::start(chain).await;

        assert!(
            spent_nullifiers(
                &mut server.node.rpc_client(),
                &[deposit.nullifier()],
                BlockNumber::GENESIS,
                12.into()
            )
            .await
            .unwrap()
            .is_empty()
        );
    }

    #[tokio::test]
    async fn invalid_nullifier_pagination_does_not_report_notes_as_unspent() {
        let nullifier = TestChain::deposit(1).nullifier();
        for checked in [0, 21] {
            let mut chain = TestChain::new(20);
            chain.invalid_checked = Some(checked);
            let server = TestServer::start(chain).await;
            assert!(
                spent_nullifiers(
                    &mut server.node.rpc_client(),
                    &[nullifier],
                    BlockNumber::GENESIS,
                    20.into()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn nullifier_checks_find_spent_notes_in_a_large_set() {
        let mut requested: Vec<_> = (0..1_500u32)
            .map(|prefix| {
                Nullifier::from_raw(Word::new([
                    miden_protocol::Felt::ZERO,
                    miden_protocol::Felt::ZERO,
                    miden_protocol::Felt::ZERO,
                    miden_protocol::Felt::new(u64::from(prefix) << 48).unwrap(),
                ]))
            })
            .collect();
        let first = requested[0];
        let last = *requested.last().unwrap();
        let mut chain = TestChain::new(20);
        chain.spent = vec![(3, first), (19, last)];
        let server = TestServer::start(chain).await;
        requested.push(first);

        assert_eq!(
            spent_nullifiers(
                &mut server.node.rpc_client(),
                &requested,
                BlockNumber::GENESIS,
                20.into()
            )
            .await
            .unwrap(),
            HashSet::from([first, last])
        );
    }
}
