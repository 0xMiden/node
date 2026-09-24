use miden_protobuf::{ConversionError, Verify};
use miden_protocol::note::NoteScript;

use crate::generated as proto;

impl Verify for proto::rpc::DecodedMaybeNoteScript {
    type Verified = Option<NoteScript>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.script.verify()
    }
}
