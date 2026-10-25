//! Account scans resumed with block ranges after their original target has been pruned.

use std::collections::BTreeMap;

use pretty_assertions::assert_eq;

use super::*;

#[derive(Clone, Copy)]
enum Kind {
    Vault,
    Maps,
}

type Update = (u32, u32, Option<u64>);

/// Uses one logical history for vaults and maps, including equal keys in distinct map slots.
struct History {
    db: TestDb,
    account: AccountId,
    kind: Kind,
}

impl History {
    fn new(kind: Kind) -> Self {
        let db = TestDb::new();
        let account = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
        create_block(&db, 0.into());
        upsert_mock_account(&db, account, 0, 0.into()).unwrap();
        Self { db, account, kind }
    }

    fn asset(key: u32, amount: u64) -> Asset {
        let mut bytes = [0; 15];
        bytes[5..9].copy_from_slice(&key.to_le_bytes());
        let issuer = AccountId::dummy(
            bytes,
            AccountIdVersion::Version1,
            AccountType::Public,
            AssetCallbackFlag::Disabled,
        );
        FungibleAsset::new(issuer, amount).unwrap().into()
    }

    fn map_key(key: u32) -> (StorageSlotName, StorageMapKey) {
        (
            StorageSlotName::mock((key % 2 + 1) as usize),
            StorageMapKey::new(num_to_word(u64::from(key / 2))),
        )
    }

    fn write(&self, block: u32, key: u32, amount: Option<u64>) {
        match self.kind {
            Kind::Vault => {
                insert_vault_asset(
                    &self.db,
                    self.account,
                    block.into(),
                    Self::asset(key, 1).id(),
                    amount.map(|amount| Self::asset(key, amount)),
                )
                .unwrap();
            },
            Kind::Maps => {
                let (slot, key) = Self::map_key(key);
                insert_storage_map_value(
                    &self.db,
                    self.account,
                    block.into(),
                    slot,
                    key,
                    num_to_word(amount.unwrap_or(0)),
                )
                .unwrap();
            },
        }
    }

    fn advance(&self, from: u32, to: u32) {
        for block in from..=to {
            create_block(&self.db, block.into());
            upsert_mock_account(&self.db, self.account, 0, block.into()).unwrap();
        }
    }

    fn scan(&self, from: u32, target: u32, size: usize) -> Result<Vec<Update>, DatabaseError> {
        let mut updates = vec![];
        let size = NonZeroUsize::new(size).unwrap();
        let range = BlockNumber::from(from)..=BlockNumber::from(target);
        match self.kind {
            Kind::Vault => {
                let mut cursor = None;
                loop {
                    let page = select_account_vault_updates_v2(
                        &self.db,
                        self.account,
                        range.clone(),
                        cursor,
                        size,
                    )?;
                    updates.extend(page.values.into_iter().map(|row| {
                        let key =
                            (0..7).find(|key| Self::asset(*key, 1).id() == row.vault_key).unwrap();
                        let amount =
                            row.asset.map(|asset| asset.as_fungible().unwrap().amount().as_u64());
                        (row.block_num.as_u32(), key, amount)
                    }));
                    match page.next_cursor {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
            },
            Kind::Maps => {
                let mut cursor = None;
                loop {
                    let account = self.account;
                    let range = range.clone();
                    let page = self.db.read(move |tx| {
                        queries::AccountStorageMapUpdatesV2::new(
                            account,
                            crate::ScopedBlockRange::new_unchecked(range),
                            size,
                        )
                        .page(tx, &cursor)
                    })?;
                    updates.extend(page.items.into_iter().map(|row| {
                        let key = (0..7)
                            .find(|key| Self::map_key(*key) == (row.slot_name.clone(), row.key))
                            .unwrap();
                        let amount =
                            (row.value != Word::empty()).then(|| row.value[3].as_canonical_u64());
                        (row.block_num.as_u32(), key, amount)
                    }));
                    match page.next.flatten() {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
            },
        }
        assert!(updates.windows(2).all(|rows| rows[0].0 <= rows[1].0));
        Ok(updates)
    }
}

fn apply(state: &mut BTreeMap<u32, u64>, updates: impl IntoIterator<Item = Update>) {
    for (_, key, value) in updates {
        if let Some(value) = value {
            state.insert(key, value);
        } else {
            state.remove(&key);
        }
    }
}

fn resume_twice(kind: Kind) {
    for size in [1, 2, 256] {
        let history = History::new(kind);
        history.write(0, 0, Some(10));
        history.advance(1, 1);
        history.write(1, 1, Some(11));
        history.write(1, 2, Some(12));
        history.advance(2, 3);
        history.write(3, 3, Some(13));
        history.write(3, 4, Some(14));
        history.advance(4, 5);
        history.write(5, 5, Some(15));
        let first = history.scan(1, 5, size).unwrap();
        let interrupted = first.iter().position(|row| row.0 == 3).unwrap();
        let checkpoint = first[interrupted].0 - 1;
        assert_eq!(checkpoint, 2);
        let mut staged = BTreeMap::from([(0, 10)]);
        apply(&mut staged, first[..interrupted].iter().copied());
        assert_eq!(staged, BTreeMap::from([(0, 10), (1, 11), (2, 12)]));

        for (block, key, value) in
            [(6, 1, Some(61)), (7, 2, None), (8, 3, Some(83)), (9, 6, Some(96))]
        {
            history.advance(block, block);
            history.write(block, key, value);
        }
        history.advance(10, 56);
        let deleted = prune_history(&history.db, 56.into()).unwrap();
        assert!(deleted.0 + deleted.1 > 0, "superseded versions must actually be pruned");
        assert_matches!(history.scan(1, 5, size), Err(DatabaseError::BlockPruned { .. }));
        let second = history.scan(checkpoint + 1, 56, size).unwrap();
        assert!(second.iter().all(|row| row.0 > checkpoint));
        let mut complete = staged.clone();
        apply(&mut complete, second.iter().copied());
        assert_eq!(
            complete,
            BTreeMap::from([(0, 10), (1, 61), (3, 83), (4, 14), (5, 15), (6, 96)])
        );
        let mut fresh = BTreeMap::new();
        apply(&mut fresh, history.scan(0, 56, size).unwrap());
        assert_eq!(complete, fresh);

        let interrupted = second.iter().position(|row| row.0 == 8).unwrap();
        let checkpoint = second[interrupted].0 - 1;
        assert_eq!(checkpoint, 7);
        apply(&mut staged, second[..interrupted].iter().copied());
        for (block, key, value) in [(57, 4, Some(574)), (58, 1, None), (59, 2, Some(592))] {
            history.advance(block, block);
            history.write(block, key, value);
        }
        history.advance(60, 112);
        let deleted = prune_history(&history.db, 112.into()).unwrap();
        assert!(deleted.0 + deleted.1 > 0);
        assert_matches!(history.scan(3, 56, size), Err(DatabaseError::BlockPruned { .. }));
        let last = history.scan(checkpoint + 1, 112, size).unwrap();
        assert!(last.iter().all(|row| row.0 > checkpoint));
        apply(&mut staged, last);
        assert_eq!(
            staged,
            BTreeMap::from([(0, 10), (2, 592), (3, 83), (4, 574), (5, 15), (6, 96)])
        );
        let mut fresh = BTreeMap::new();
        apply(&mut fresh, history.scan(0, 112, size).unwrap());
        assert_eq!(staged, fresh);
    }
}

/// Retargeting must replace previously staged assets and preserve deletions after pruning.
#[test]
fn vault_sync_resumption_survives_pruning_and_retargeting() {
    resume_twice(Kind::Vault);
}

/// Retargeting must reconcile map keys independently across slots and retained versions.
#[test]
fn storage_map_sync_resumption_survives_pruning_and_retargeting() {
    resume_twice(Kind::Maps);
}

/// Bootstrap replay includes genesis; squashed prefixes are not historical account snapshots.
#[test]
fn account_sync_resumption_replays_genesis_and_handles_empty_suffixes() {
    for kind in [Kind::Vault, Kind::Maps] {
        let history = History::new(kind);
        history.write(0, 1, Some(11));
        history.write(0, 2, Some(12));
        let genesis = history.scan(0, 0, 1).unwrap();
        assert_eq!(genesis.len(), 2);
        assert_eq!(history.scan(0, 0, 2).unwrap(), genesis);
        history.advance(1, 3);
        history.write(3, 3, Some(33));
        history.advance(4, 5);
        history.write(5, 1, Some(51));
        let rows = history.scan(0, 5, 1).unwrap();
        assert_eq!(rows, vec![(0, 2, Some(12)), (3, 3, Some(33)), (5, 1, Some(51))]);
        // The block-0 prefix omits A even though A existed at block 0: it is squashed into block 5.
        let mut state = BTreeMap::from([(2, 12)]);
        apply(&mut state, history.scan(3, 5, 1).unwrap());
        assert_eq!(state, BTreeMap::from([(1, 51), (2, 12), (3, 33)]));
        history.advance(6, 10);
        assert!(history.scan(6, 10, 1).unwrap().is_empty());
    }
}

/// Block ranges cannot continue inside a block: excluding it loses its unread records.
#[test]
fn account_sync_resumption_cannot_checkpoint_partial_single_block() {
    for kind in [Kind::Vault, Kind::Maps] {
        let history = History::new(kind);
        for key in 1..=3 {
            history.write(0, key, Some(u64::from(key)));
        }
        history.advance(1, 5);
        let initial = history.scan(0, 5, 1).unwrap();
        assert_eq!(initial.len(), 3);
        // After receiving just the first record, no block is complete and genesis must be replayed.
        let checkpoint = initial[0].0.checked_sub(1);
        assert_eq!(checkpoint, None);
        history.advance(6, 56);
        prune_history(&history.db, 56.into()).unwrap();
        let replay = history.scan(0, 56, 1).unwrap();
        assert_eq!(replay, initial);
        assert_eq!(replay[0].0.checked_sub(1), checkpoint);
        assert!(
            history.scan(1, 56, 1).unwrap().is_empty(),
            "excluding genesis loses unread keys"
        );
    }
}
