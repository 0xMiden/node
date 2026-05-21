use std::net::SocketAddr;

use anyhow::Context;

/// A sealed extension trait for [`url::Url`] that adds convenience functions for binding and
/// connecting to the url.
pub trait UrlExt: private::Sealed {
    /// # Errors
    ///
    /// Returns an error if the URL cannot be converted to a socket address.
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
