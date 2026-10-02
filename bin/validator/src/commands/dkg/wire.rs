use anyhow::{Context, ensure};
use iroh::endpoint::{RecvStream as IrohRecvStream, SendStream as IrohSendStream};

/// Encodes and decodes one ceremony message without adding transport framing.
///
/// The protocol step supplies the expected byte count. Decoders must reject incomplete values
/// and trailing bytes so adjacent messages remain separate on the shared stream.
pub trait WireCodec: Sized {
    fn encode(&self) -> Vec<u8>;

    fn decode(bytes: &[u8]) -> anyhow::Result<Self>;
}

pub struct SendStream {
    inner: IrohSendStream,
}

impl SendStream {
    pub async fn write<T: WireCodec>(&mut self, value: &T) -> anyhow::Result<usize> {
        let bytes = value.encode();
        let bytes_written = bytes.len();
        self.inner.write_all(&bytes).await.context("failed to write wire message")?;
        Ok(bytes_written)
    }

    pub fn finish(&mut self) -> anyhow::Result<()> {
        self.inner.finish().context("failed to finish wire stream")
    }

    /// Waits for the peer to acknowledge all data after the send stream is finished.
    ///
    /// Closing the connection before delivery can discard buffered messages.
    pub async fn wait_for_delivery(&self) -> anyhow::Result<()> {
        let stopped = self.inner.stopped().await.context("failed to deliver wire stream")?;
        ensure!(stopped.is_none(), "peer stopped the wire stream before delivery: {stopped:?}");
        Ok(())
    }

    #[cfg(test)]
    pub fn into_inner(self) -> IrohSendStream {
        self.inner
    }
}

impl From<IrohSendStream> for SendStream {
    fn from(inner: IrohSendStream) -> Self {
        Self { inner }
    }
}

pub struct RecvStream {
    inner: IrohRecvStream,
}

impl RecvStream {
    #[cfg(test)]
    pub fn into_inner(self) -> IrohRecvStream {
        self.inner
    }

    /// Reads and decodes exactly the byte count selected by the current protocol step.
    ///
    /// The count must come from local configuration or a fixed message size, not an unchecked
    /// peer-supplied length, because it determines the receive allocation.
    pub async fn read_exact<T: WireCodec>(&mut self, bytes: usize) -> anyhow::Result<T> {
        let mut bytes = vec![0; bytes];
        self.inner.read_exact(&mut bytes).await.context("failed to read wire message")?;
        T::decode(&bytes).context("failed to decode wire message")
    }
}

impl From<IrohRecvStream> for RecvStream {
    fn from(inner: IrohRecvStream) -> Self {
        Self { inner }
    }
}
