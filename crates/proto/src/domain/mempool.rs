use std::collections::HashSet;

use miden_protocol::account::delta::AccountUpdateDetails;
use miden_protocol::block::BlockHeader;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::Serializable;
use miden_standards::note::AccountTargetNetworkNote;

use crate::errors::{
    ConversionError,
    ConversionResultExt,
    DecodeBytesExt,
    GrpcDecodeExt as _,
    grpc_decode,
};
use crate::generated as proto;

#[derive(Debug, Clone)]
pub enum MempoolEvent {
    TransactionAdded {
        id: TransactionId,
        nullifiers: Vec<Nullifier>,
        network_notes: Vec<AccountTargetNetworkNote>,
        account_delta: Option<AccountUpdateDetails>,
    },
    BlockCommitted {
        // Box'd as this struct is quite large and triggers clippy.
        header: Box<BlockHeader>,
        txs: Vec<TransactionId>,
    },
    TransactionsReverted(HashSet<TransactionId>),
}

impl MempoolEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            MempoolEvent::TransactionAdded { .. } => "TransactionAdded",
            MempoolEvent::BlockCommitted { .. } => "BlockCommitted",
            MempoolEvent::TransactionsReverted(_) => "TransactionsReverted",
        }
    }
}

impl From<MempoolEvent> for proto::block_producer::MempoolEvent {
    fn from(event: MempoolEvent) -> Self {
        let event = match event {
            MempoolEvent::TransactionAdded {
                id,
                nullifiers,
                network_notes,
                account_delta,
            } => {
                let event = proto::block_producer::mempool_event::TransactionAdded {
                    id: Some(id.into()),
                    nullifiers: nullifiers.into_iter().map(Into::into).collect(),
                    network_notes: network_notes.into_iter().map(Into::into).collect(),
                    network_account_delta: account_delta
                        .as_ref()
                        .map(AccountUpdateDetails::to_bytes),
                };

                proto::block_producer::mempool_event::Event::TransactionAdded(event)
            },
            MempoolEvent::BlockCommitted { header, txs } => {
                proto::block_producer::mempool_event::Event::BlockCommitted(
                    proto::block_producer::mempool_event::BlockCommitted {
                        block_header: Some(header.as_ref().into()),
                        transactions: txs.into_iter().map(Into::into).collect(),
                    },
                )
            },
            MempoolEvent::TransactionsReverted(txs) => {
                proto::block_producer::mempool_event::Event::TransactionsReverted(
                    proto::block_producer::mempool_event::TransactionsReverted {
                        reverted: txs.into_iter().map(Into::into).collect(),
                    },
                )
            },
        }
        .into();

        Self { event }
    }
}

#[grpc_decode]
impl TryFrom<proto::block_producer::MempoolEvent> for MempoolEvent {
    type Error = ConversionError;

    fn try_from(event: proto::block_producer::MempoolEvent) -> Result<Self, Self::Error> {
        let event = event.event.ok_or(ConversionError::missing_field::<
            proto::block_producer::MempoolEvent,
        >("event"))?;

        match event {
            proto::block_producer::mempool_event::Event::TransactionAdded(tx) => {
                let id = tx.id.decode()?;
                let nullifiers = tx
                    .nullifiers
                    .into_iter()
                    .map(Nullifier::try_from)
                    .collect::<Result<_, _>>()
                    .context("nullifiers")?;
                let network_notes = tx
                    .network_notes
                    .into_iter()
                    .map(AccountTargetNetworkNote::try_from)
                    .collect::<Result<_, _>>()
                    .context("network_notes")?;
                let account_delta = tx
                    .network_account_delta
                    .as_deref()
                    .map(|bytes| AccountUpdateDetails::decode_bytes(bytes, "account_delta"))
                    .transpose()?;

                Ok(Self::TransactionAdded {
                    id,
                    nullifiers,
                    network_notes,
                    account_delta,
                })
            },
            proto::block_producer::mempool_event::Event::BlockCommitted(block_committed) => {
                let header = block_committed.block_header.decode()?;
                let header = Box::new(header);
                let txs = block_committed
                    .transactions
                    .into_iter()
                    .map(TransactionId::try_from)
                    .collect::<Result<_, _>>()
                    .context("transactions")?;

                Ok(Self::BlockCommitted { header, txs })
            },
            proto::block_producer::mempool_event::Event::TransactionsReverted(txs) => {
                let txs = txs
                    .reverted
                    .into_iter()
                    .map(TransactionId::try_from)
                    .collect::<Result<_, _>>()
                    .context("reverted")?;

                Ok(Self::TransactionsReverted(txs))
            },
        }
    }
}
