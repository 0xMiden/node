use std::net::SocketAddr;

use anyhow::Context;

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

/// Binds a TCP listener to the given address with `SO_REUSEADDR` enabled.
///
/// This allows the listener to bind to a port that is in the `TIME_WAIT` state, which is common
/// when rapidly restarting services.
pub fn bind_reuseaddr(addr: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .context("Failed to create TCP socket")?;

    socket.set_reuseaddr(true).context("Failed to set SO_REUSEADDR")?;
    socket.bind(addr).context("Failed to bind socket")?;

    socket.listen(1024).context("Failed to listen on socket")
}

mod private {
    pub trait Sealed {}
    impl Sealed for url::Url {}
}

pub mod connect_info;
mod layers;
pub use layers::*;
