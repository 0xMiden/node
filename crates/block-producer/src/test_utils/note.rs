use miden_protocol::note::Note;
use miden_protocol::transaction::{OutputNote, PublicOutputNote};
use miden_standards::testing::note::NoteBuilder;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::test_utils::account::mock_account_id;

pub fn mock_note(num: u8) -> Note {
    let sender = mock_account_id(num);
    NoteBuilder::new(sender, ChaCha20Rng::from_seed([num; 32])).build().unwrap()
}

pub fn mock_output_note(num: u8) -> OutputNote {
    OutputNote::Public(PublicOutputNote::new(mock_note(num)).unwrap())
}
