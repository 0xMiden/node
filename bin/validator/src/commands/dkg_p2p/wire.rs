use anyhow::Context;
use iroh::endpoint::{RecvStream as IrohRecvStream, SendStream as IrohSendStream};

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
