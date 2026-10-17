//! Protobuf files for benchmark transactions and inputs.

use std::path::Path;

use anyhow::{Context, Result};
use miden_node_persistence::ProtobufValue;
use miden_node_persistence::generated::{BenchmarkTransactionInputs, BenchmarkTransactions};
use miden_node_persistence::prost::Message;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};

pub(crate) fn write_transactions(path: &Path, transactions: &[ProvenTransaction]) -> Result<()> {
    let message = BenchmarkTransactions {
        transactions: transactions.iter().map(ProtobufValue::to_proto).collect(),
    };
    fs_err::write(path, message.encode_to_vec())
        .with_context(|| format!("failed to write benchmark transactions to {}", path.display()))
}

pub(crate) fn read_transactions(path: &Path) -> Result<Vec<ProvenTransaction>> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read {}: run `create-proofs` first", path.display()))?;
    let message = BenchmarkTransactions::decode(bytes.as_slice()).with_context(|| {
        format!("failed to decode benchmark transactions in {}", path.display())
    })?;
    message
        .transactions
        .into_iter()
        .enumerate()
        .map(|(index, transaction)| {
            ProvenTransaction::from_proto(transaction)
                .with_context(|| format!("invalid transaction {index} in {}", path.display()))
        })
        .collect()
}

pub(crate) fn write_inputs(path: &Path, inputs: &[TransactionInputs]) -> Result<()> {
    let message = BenchmarkTransactionInputs {
        inputs: inputs.iter().map(ProtobufValue::to_proto).collect(),
    };
    fs_err::write(path, message.encode_to_vec())
        .with_context(|| format!("failed to write benchmark inputs to {}", path.display()))
}

pub(crate) fn read_inputs(path: &Path) -> Result<Vec<TransactionInputs>> {
    let bytes = fs_err::read(path)
        .with_context(|| format!("failed to read {}: run `create-proofs` first", path.display()))?;
    let message = BenchmarkTransactionInputs::decode(bytes.as_slice())
        .with_context(|| format!("failed to decode benchmark inputs in {}", path.display()))?;
    message
        .inputs
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            TransactionInputs::from_proto(input)
                .with_context(|| format!("invalid input {index} in {}", path.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::{Account, AccountCode, AccountStorage, AccountUpdateDetails};
    use miden_protocol::asset::AssetVault;
    use miden_protocol::block::{BlockHeader, BlockNumber};
    use miden_protocol::protocol_config::ProtocolConfig;
    use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
    use miden_protocol::transaction::{
        InputNoteCommitment,
        InputNotes,
        OutputNote,
        PartialBlockchain,
        TxAccountUpdate,
    };
    use miden_protocol::{Felt, Word};

    use super::*;

    fn transaction(seed: u32) -> ProvenTransaction {
        let update = TxAccountUpdate::new(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            Word::empty(),
            Word::from([seed, 0, 0, 0]),
            Word::empty(),
            AccountUpdateDetails::Private,
        )
        .unwrap();
        ProvenTransaction::new(
            update,
            Vec::<InputNoteCommitment>::new(),
            Vec::<OutputNote>::new(),
            BlockNumber::GENESIS,
            Word::empty(),
            (seed + 1).into(),
            miden_protocol::testing::dummy_execution_proof(),
        )
        .unwrap()
    }

    fn inputs(nonce: u32) -> TransactionInputs {
        let account = Account::new_existing(
            ACCOUNT_ID_PRIVATE_SENDER.try_into().unwrap(),
            AssetVault::mock(),
            AccountStorage::mock(),
            AccountCode::mock(),
            Felt::from(nonce),
        );
        let blockchain = PartialBlockchain::default();
        let header = BlockHeader::mock(0_u32, Some(blockchain.peaks().hash_peaks()), None, &[]);
        TransactionInputs::new(
            (&account).into(),
            header,
            ProtocolConfig::mock(),
            blockchain,
            InputNotes::default(),
        )
        .unwrap()
    }

    #[test]
    fn empty_collections_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tx_path = dir.path().join("mint_txs.bin");
        let input_path = dir.path().join("mint_tx_inputs.bin");
        write_transactions(&tx_path, &[]).unwrap();
        write_inputs(&input_path, &[]).unwrap();
        assert!(read_transactions(&tx_path).unwrap().is_empty());
        assert!(read_inputs(&input_path).unwrap().is_empty());
    }

    #[test]
    fn nonempty_collections_preserve_order_state_and_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transactions.bin");
        let transactions = vec![transaction(2), transaction(1)];
        write_transactions(&path, &transactions).unwrap();
        let decoded = read_transactions(&path).unwrap();
        assert_eq!(decoded, transactions);
        for (actual, expected) in decoded.iter().zip(&transactions) {
            assert_eq!(actual.proof().to_bytes(), expected.proof().to_bytes());
        }
        let message =
            BenchmarkTransactions::decode(fs_err::read(&path).unwrap().as_slice()).unwrap();
        assert_eq!(message.transactions.len(), 2);

        let expected = vec![inputs(2), inputs(1)];
        write_inputs(&path, &expected).unwrap();
        assert_eq!(read_inputs(&path).unwrap(), expected);
        let message =
            BenchmarkTransactionInputs::decode(fs_err::read(&path).unwrap().as_slice()).unwrap();
        assert_eq!(message.inputs.len(), 2);
    }

    #[test]
    fn malformed_entries_and_wire_data_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.bin");
        fs_err::write(
            &path,
            BenchmarkTransactions {
                transactions: vec![
                    miden_node_proto::generated::transaction::ProvenTransaction::default(),
                ],
            }
            .encode_to_vec(),
        )
        .unwrap();
        let error = read_transactions(&path).unwrap_err();
        assert!(error.to_string().contains("transaction 0"));
        assert!(error.to_string().contains("invalid.bin"));
        fs_err::write(
            &path,
            BenchmarkTransactionInputs {
                inputs: vec![miden_node_proto::generated::transaction::TransactionInputs::default()],
            }
            .encode_to_vec(),
        )
        .unwrap();
        let error = read_inputs(&path).unwrap_err();
        assert!(error.to_string().contains("input 0"));
        assert!(error.to_string().contains("invalid.bin"));
        fs_err::write(&path, [0xff]).unwrap();
        assert!(read_transactions(&path).is_err());
        assert!(read_inputs(&path).is_err());
    }

    #[test]
    fn unknown_fields_are_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extended.bin");
        let expected = vec![transaction(1)];
        let mut bytes = BenchmarkTransactions {
            transactions: expected.iter().map(ProtobufValue::to_proto).collect(),
        }
        .encode_to_vec();
        bytes.extend([0x78, 0x01]);
        fs_err::write(&path, bytes).unwrap();
        assert_eq!(read_transactions(&path).unwrap(), expected);

        let expected = vec![inputs(1)];
        let mut bytes = BenchmarkTransactionInputs {
            inputs: expected.iter().map(ProtobufValue::to_proto).collect(),
        }
        .encode_to_vec();
        bytes.extend([0x78, 0x01]);
        fs_err::write(&path, bytes).unwrap();
        assert_eq!(read_inputs(&path).unwrap(), expected);
    }
}
