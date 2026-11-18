//! An upstream server and how to reach it.

use pingora_core::Result;
use pingora_core::protocols::ALPN;
use pingora_core::upstreams::peer::HttpPeer;
use std::net::SocketAddr;
use std::time::Duration;

/// Timeouts applied to every connection to an origin.
#[derive(Debug, Clone, Copy)]
pub struct PeerOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
}

impl From<&piano_config::Upstream> for PeerOptions {
    fn from(u: &piano_config::Upstream) -> Self {
        Self {
            connect_timeout: u.connect_timeout.get(),
            read_timeout: u.read_timeout.get(),
            idle_timeout: u.idle_timeout.get(),
        }
    }
}

/// A resolved upstream: a lowercase host name (used for SNI and `Host`) and the one
/// address chosen for it.
#[derive(Debug, Clone)]
pub struct Origin {
    pub host: String,
    pub port: u16,
    pub addr: SocketAddr,
    pub options: PeerOptions,
}

impl Origin {
    /// The value for the upstream `Host` header.
    pub fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// A peer for one connection attempt. SNI is always set: an empty SNI would turn
    /// off certificate verification in the connector.
    pub fn peer(&self) -> Result<HttpPeer> {
        let mut peer = HttpPeer::new(self.addr, true, self.host.clone())?;
        let o = &mut peer.options;
        o.alpn = ALPN::H1;
        o.verify_cert = true;
        o.verify_hostname = true;
        o.connection_timeout = Some(self.options.connect_timeout);
        o.total_connection_timeout = Some(self.options.connect_timeout * 2);
        o.read_timeout = Some(self.options.read_timeout);
        o.write_timeout = Some(self.options.read_timeout);
        o.idle_timeout = Some(self.options.idle_timeout);
        Ok(peer)
    }
}
