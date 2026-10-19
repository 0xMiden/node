use std::net::SocketAddr;

use anyhow::Context;

/// Maximum encoded bytes accepted in a gRPC message unless explicitly configured.
pub const DEFAULT_MAX_DECODING_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// A sealed extension trait for [`url::Url`] that adds convenience functions for binding and
/// connecting to the url.
pub trait UrlExt: private::Sealed {
    fn to_socket(&self) -> anyhow::Result<SocketAddr>;
}

impl UrlExt for url::Url {
    fn to_socket(&self) -> anyhow::Result<SocketAddr> {
        self.socket_addrs(|| None)?
            .into_iter()
            .next()
            .with_context(|| format!("failed to convert url {self} to socket address"))
    }
}

mod private {
    pub trait Sealed {}
    impl Sealed for url::Url {}
}

mod layers;
pub use layers::*;

mod server;
pub use server::{server_builder, tcp_incoming};
