use std::fmt::{Debug, Display, Formatter};

use hex::{FromHex, ToHex};
use miden_protocol::account::StorageMapKey;
use miden_protocol::note::NoteId;
use miden_protocol::{Felt, StarkField, Word};

use crate::errors::ConversionError;
use crate::generated as proto;

// CONSTANTS
// ================================================================================================

pub const DIGEST_DATA_SIZE: usize = 32;

// FORMATTING
// ================================================================================================

impl Display for proto::primitives::Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode_hex::<String>())
    }
}

impl Debug for proto::primitives::Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl ToHex for &proto::primitives::Digest {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        (*self).encode_hex()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        (*self).encode_hex_upper()
    }
}

impl ToHex for proto::primitives::Digest {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        let mut data: Vec<char> = Vec::with_capacity(DIGEST_DATA_SIZE);
        data.extend(format!("{:016x}", self.d0).chars());
        data.extend(format!("{:016x}", self.d1).chars());
        data.extend(format!("{:016x}", self.d2).chars());
        data.extend(format!("{:016x}", self.d3).chars());
        data.into_iter().collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        let mut data: Vec<char> = Vec::with_capacity(DIGEST_DATA_SIZE);
        data.extend(format!("{:016X}", self.d0).chars());
        data.extend(format!("{:016X}", self.d1).chars());
        data.extend(format!("{:016X}", self.d2).chars());
        data.extend(format!("{:016X}", self.d3).chars());
        data.into_iter().collect()
    }
}

impl FromHex for proto::primitives::Digest {
    type Error = ConversionError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let data = hex::decode(hex)?;

        match data.len() {
            size if size < DIGEST_DATA_SIZE => Err(ConversionError::message(format!(
                "not enough data, expected {DIGEST_DATA_SIZE}, got {size}"
            ))),
            size if size > DIGEST_DATA_SIZE => Err(ConversionError::message(format!(
                "too much data, expected {DIGEST_DATA_SIZE}, got {size}"
            ))),
            _ => {
                let d0 = u64::from_be_bytes(data[..8].try_into().unwrap());
                let d1 = u64::from_be_bytes(data[8..16].try_into().unwrap());
                let d2 = u64::from_be_bytes(data[16..24].try_into().unwrap());
                let d3 = u64::from_be_bytes(data[24..32].try_into().unwrap());

                Ok(proto::primitives::Digest { d0, d1, d2, d3 })
            },
        }
    }
}

// INTO
// ================================================================================================

impl From<[u64; 4]> for proto::primitives::Digest {
    fn from(value: [u64; 4]) -> Self {
        Self {
            d0: value[0],
            d1: value[1],
            d2: value[2],
            d3: value[3],
        }
    }
}

impl From<&[u64; 4]> for proto::primitives::Digest {
    fn from(value: &[u64; 4]) -> Self {
        (*value).into()
    }
}

impl From<[Felt; 4]> for proto::primitives::Digest {
    fn from(value: [Felt; 4]) -> Self {
        Self {
            d0: value[0].as_int(),
            d1: value[1].as_int(),
            d2: value[2].as_int(),
            d3: value[3].as_int(),
        }
    }
}

impl From<&[Felt; 4]> for proto::primitives::Digest {
    fn from(value: &[Felt; 4]) -> Self {
        (*value).into()
    }
}

impl From<Word> for proto::primitives::Digest {
    fn from(value: Word) -> Self {
        Self {
            d0: value[0].as_int(),
            d1: value[1].as_int(),
            d2: value[2].as_int(),
            d3: value[3].as_int(),
        }
    }
}

impl From<&Word> for proto::primitives::Digest {
    fn from(value: &Word) -> Self {
        (*value).into()
    }
}

impl From<StorageMapKey> for proto::primitives::Digest {
    fn from(value: StorageMapKey) -> Self {
        Into::<Word>::into(value).into()
    }
}

impl From<&StorageMapKey> for proto::primitives::Digest {
    fn from(value: &StorageMapKey) -> Self {
        (*value).into()
    }
}

impl From<&NoteId> for proto::primitives::Digest {
    fn from(value: &NoteId) -> Self {
        value.as_word().into()
    }
}

impl From<NoteId> for proto::primitives::Digest {
    fn from(value: NoteId) -> Self {
        value.as_word().into()
    }
}

// FROM DIGEST
// ================================================================================================

impl From<proto::primitives::Digest> for [u64; 4] {
    fn from(value: proto::primitives::Digest) -> Self {
        [value.d0, value.d1, value.d2, value.d3]
    }
}

impl TryFrom<proto::primitives::Digest> for [Felt; 4] {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        if [value.d0, value.d1, value.d2, value.d3]
            .iter()
            .any(|v| *v >= <Felt as StarkField>::MODULUS)
        {
            return Err(ConversionError::message("value is not in the range 0..MODULUS"));
        }

        Ok([
            Felt::new(value.d0),
            Felt::new(value.d1),
            Felt::new(value.d2),
            Felt::new(value.d3),
        ])
    }
}

impl TryFrom<proto::primitives::Digest> for Word {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        Ok(Self::new(value.try_into()?))
    }
}

impl TryFrom<proto::primitives::Digest> for StorageMapKey {
    type Error = ConversionError;

    fn try_from(value: proto::primitives::Digest) -> Result<Self, Self::Error> {
        Ok(StorageMapKey::new(value.try_into()?))
    }
}

impl TryFrom<&proto::primitives::Digest> for [Felt; 4] {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Digest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

impl TryFrom<&proto::primitives::Digest> for Word {
    type Error = ConversionError;

    fn try_from(value: &proto::primitives::Digest) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use hex::{FromHex, ToHex};
    use proptest::prelude::*;

    use crate::generated as proto;

    #[test]
    fn hex_digest() {
        let digest = proto::primitives::Digest {
            d0: 0x306A_B7A6_F795_CAD7,
            d1: 0x4927_3716_D099_AA04,
            d2: 0xF741_2C3D_E726_4450,
            d3: 0x976B_8764_9DB3_B82F,
        };
        let encoded: String = ToHex::encode_hex(&digest);
        let round_trip: Result<proto::primitives::Digest, _> =
            FromHex::from_hex::<&[u8]>(encoded.as_ref());
        assert_eq!(digest, round_trip.unwrap());

        let digest = proto::primitives::Digest { d0: 0, d1: 0, d2: 0, d3: 0 };
        let encoded: String = ToHex::encode_hex(&digest);
        let round_trip: Result<proto::primitives::Digest, _> =
            FromHex::from_hex::<&[u8]>(encoded.as_ref());
        assert_eq!(digest, round_trip.unwrap());
    }

    proptest! {
        #[test]
        fn encode_decode(
            d0: u64,
            d1: u64,
            d2: u64,
            d3: u64,
        ) {
            let digest = proto::primitives::Digest { d0, d1, d2, d3 };
            let encoded: String = ToHex::encode_hex(&digest);
            let round_trip: Result<proto::primitives::Digest, _> = FromHex::from_hex::<&[u8]>(encoded.as_ref());
            assert_eq!(digest, round_trip.unwrap());
        }
    }
}
