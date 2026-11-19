use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_crypto::merkle::smt::{
    ForestInMemoryBackend,
    LargeSmtForest,
    LineageId,
    SmtForestMutationSet,
    SmtForestOperation,
    SmtForestUpdateBatch,
    SmtUpdateBatch,
    TreeId,
};
use miden_protocol::{Hasher, Word};

const INITIAL_VERSION: u64 = 1;
const RECREATED_VERSION: u64 = 2;

fn lineage() -> LineageId {
    LineageId::new([1; 32])
}

fn word(value: u32) -> Word {
    Word::from([value, 0, 0, 0])
}

fn key(value: u32) -> Word {
    Hasher::hash(&value.to_le_bytes())
}

fn forest_with_entries(entry_count: u32) -> LargeSmtForest<ForestInMemoryBackend> {
    let mut forest = LargeSmtForest::new(ForestInMemoryBackend::new()).unwrap();
    let updates =
        SmtUpdateBatch::new((0..entry_count).map(|index| {
            SmtForestOperation::insert(key(index + 1), word(entry_count + index + 1))
        }));
    forest.add_lineage(lineage(), INITIAL_VERSION, updates).unwrap();
    forest
}

/// Mirrors storage-map `Create` preparation when the lineage already contains entries.
fn prepare_recreation(
    forest: &LargeSmtForest<ForestInMemoryBackend>,
) -> SmtForestMutationSet<ForestInMemoryBackend> {
    let lineage = lineage();
    let tree = TreeId::new(lineage, INITIAL_VERSION);
    let removals = forest
        .entries(tree)
        .unwrap()
        .map(|entry| SmtForestOperation::remove(entry.unwrap().key));
    let mut batch = SmtForestUpdateBatch::empty();
    batch.add_operations(lineage, removals);
    batch.operations(lineage).add_insert(key(u32::MAX - 1), word(u32::MAX));

    forest.compute_forest_mutations(RECREATED_VERSION, batch).unwrap()
}

fn bench_storage_map_recreation(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_state_forest_storage_map_recreation");

    for entry_count in [16, 256, 4_096, 16_384] {
        let forest = forest_with_entries(entry_count);
        group.bench_with_input(BenchmarkId::from_parameter(entry_count), &entry_count, |b, _| {
            b.iter(|| black_box(prepare_recreation(black_box(&forest))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_storage_map_recreation);
criterion_main!(benches);
