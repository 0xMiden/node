use miden_protobuf::{ConversionError, Verify};
use miden_protocol::note::NoteScript;

use crate::generated as proto;

impl Verify for proto::miden::node::v1::DecodedGetNoteScriptByRootResponse {
    type Verified = Option<NoteScript>;
    type Error = ConversionError;

    fn verify(self) -> Result<Self::Verified, Self::Error> {
        self.script.verify()
    }
}

impl From<proto::miden::node::v1::NoteSyncRecord> for proto::miden::node::v2::NoteSyncRecord {
    fn from(record: proto::miden::node::v1::NoteSyncRecord) -> Self {
        use proto::miden::node::{v1, v2};

        Self {
            inclusion_proof: record.inclusion_proof,
            metadata: record.metadata.map(|meta| v2::NoteSyncMetadata {
                sender: meta.sender,
                version: meta.version,
                note_type: meta.note_type,
                tag: meta.tag,
                attachments: meta
                    .attachments
                    .into_iter()
                    .map(|entry| v2::NoteSyncAttachment {
                        scheme: entry.scheme,
                        payload: entry.payload.map(|payload| match payload {
                            v1::note_sync_attachment::Payload::Value(word) => {
                                v2::note_sync_attachment::Payload::Value(word)
                            },
                            v1::note_sync_attachment::Payload::Commitment(word) => {
                                v2::note_sync_attachment::Payload::Commitment(word)
                            },
                        }),
                    })
                    .collect(),
            }),
        }
    }
}
