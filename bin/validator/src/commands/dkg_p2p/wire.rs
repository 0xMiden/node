use anyhow::{Context, ensure};
use iroh::endpoint::{RecvStream as IrohRecvStream, SendStream as IrohSendStream};
use miden_protocol::utils::serde::{Deserializable, Serializable};

pub trait WireCodec: Serializable + Deserializable {
    const BYTES: usize;
}

pub struct SendStream {
    inner: IrohSendStream,
}

impl SendStream {
    pub async fn write<T: WireCodec>(&mut self, value: &T) -> anyhow::Result<()> {
        let bytes = value.to_bytes();
        ensure!(bytes.len() == T::BYTES, "wire codec byte length does not match");
        self.inner.write_all(&bytes).await.context("failed to write wire message")?;
        Ok(())
    }

    pub fn finish(&mut self) -> anyhow::Result<()> {
        self.inner.finish().context("failed to finish wire stream")
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
    pub async fn read_exact<T: WireCodec>(&mut self) -> anyhow::Result<T> {
        let mut bytes = vec![0; T::BYTES];
        self.inner.read_exact(&mut bytes).await.context("failed to read wire message")?;
        T::read_from_bytes(&bytes).context("failed to decode wire message")
    }
}

impl From<IrohRecvStream> for RecvStream {
    fn from(inner: IrohRecvStream) -> Self {
        Self { inner }
    }
}
