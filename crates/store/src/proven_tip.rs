use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use miden_protocol::block::BlockNumber;

/// Single-owner handle that can advance the proven chain tip.
///
/// Not cloneable — only the proof scheduler should write.
pub struct ProvenTipWriter(Arc<AtomicU32>);

/// Cheaply cloneable handle for reading the current proven chain tip.
#[derive(Clone)]
pub struct ProvenTipReader(Arc<AtomicU32>);

impl ProvenTipWriter {
    /// Creates a new writer/reader pair initialized to `tip`.
    pub fn new(tip: BlockNumber) -> (Self, ProvenTipReader) {
        let inner = Arc::new(AtomicU32::new(tip.as_u32()));
        (Self(Arc::clone(&inner)), ProvenTipReader(inner))
    }

    /// Advances the tip to `new_tip` if it is greater than the current value.
    ///
    /// This is a no-op when `new_tip` is less than or equal to the existing tip.
    pub fn advance(&self, new_tip: BlockNumber) {
        self.0.fetch_max(new_tip.as_u32(), Ordering::Release);
    }
}

impl ProvenTipReader {
    /// Returns the current proven chain tip.
    pub fn read(&self) -> BlockNumber {
        BlockNumber::from(self.0.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_only_increases_tip() {
        let (writer, reader) = ProvenTipWriter::new(BlockNumber::from(5u32));
        assert_eq!(reader.read(), BlockNumber::from(5u32));

        // Advancing to a higher value updates the tip.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(reader.read(), BlockNumber::from(10u32));

        // Advancing to a lower value is a no-op.
        writer.advance(BlockNumber::from(7u32));
        assert_eq!(reader.read(), BlockNumber::from(10u32));

        // Advancing to the same value is a no-op.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(reader.read(), BlockNumber::from(10u32));

        // Advancing to a higher value again works.
        writer.advance(BlockNumber::from(15u32));
        assert_eq!(reader.read(), BlockNumber::from(15u32));
    }
}
