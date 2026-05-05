use miden_protocol::block::BlockNumber;
use tokio::sync::watch;

/// Cloneable handle that can advance the proven chain tip.
///
/// All clones share the same underlying watch channel, so any `advance()` call is immediately
/// visible to all receivers returned by `subscribe()`.
#[derive(Clone)]
pub struct ProvenTipWriter(watch::Sender<BlockNumber>);

impl ProvenTipWriter {
    /// Creates a new writer initialized to `tip`, returning a companion receiver.
    pub fn new(tip: BlockNumber) -> (Self, watch::Receiver<BlockNumber>) {
        let (tx, rx) = watch::channel(tip);
        (Self(tx), rx)
    }

    /// Returns the current proven chain tip.
    pub fn read(&self) -> BlockNumber {
        *self.0.borrow()
    }

    /// Advances the tip to `new_tip` if it is greater than the current value.
    ///
    /// Notifies all subscribers only when the tip actually increases.
    pub fn advance(&self, new_tip: BlockNumber) {
        self.0.send_if_modified(|current| {
            if new_tip > *current {
                *current = new_tip;
                true
            } else {
                false
            }
        });
    }

    /// Returns a new receiver that wakes on every proven-tip advance.
    pub fn subscribe(&self) -> watch::Receiver<BlockNumber> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_only_increases_tip() {
        let (writer, _rx) = ProvenTipWriter::new(BlockNumber::from(5u32));
        assert_eq!(writer.read(), BlockNumber::from(5u32));

        // Advancing to a higher value updates the tip.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to a lower value is a no-op.
        writer.advance(BlockNumber::from(7u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to the same value is a no-op.
        writer.advance(BlockNumber::from(10u32));
        assert_eq!(writer.read(), BlockNumber::from(10u32));

        // Advancing to a higher value again works.
        writer.advance(BlockNumber::from(15u32));
        assert_eq!(writer.read(), BlockNumber::from(15u32));
    }
}
