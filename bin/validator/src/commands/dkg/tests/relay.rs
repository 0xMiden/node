use std::net::Ipv4Addr;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::Builder;
use iroh::endpoint::presets::Preset;
use iroh::{RelayMode, RelayUrl};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};

/// A localhost relay with controlled discovery and no direct UDP paths.
pub struct LocalRelay {
    _server: Server,
    pub url: RelayUrl,
    pub lookup: MemoryLookup,
}

impl LocalRelay {
    pub async fn start() -> anyhow::Result<Self> {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let server = Server::spawn(config).await?;
        let url = format!("http://{}", server.http_addr().unwrap()).parse()?;
        Ok(Self {
            _server: server,
            url,
            lookup: MemoryLookup::new(),
        })
    }
}

impl Preset for &LocalRelay {
    fn apply(self, builder: Builder) -> Builder {
        builder
            .clear_address_lookup()
            .address_lookup(self.lookup.clone())
            .relay_mode(RelayMode::Custom(self.url.clone().into()))
            .clear_ip_transports()
    }
}
