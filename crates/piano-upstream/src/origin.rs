//! An upstream server and how to reach it.

use crate::resolve::Addrs;
use pingora_core::Result;
use pingora_core::protocols::ALPN;
use pingora_core::protocols::l4::ext::TcpKeepalive;
use pingora_core::upstreams::peer::HttpPeer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// TCP keepalive for every connection, client and upstream side alike. It tells a
/// silent peer from a vanished one (a phone that changed networks, a host that went
/// away without closing), which no read timeout can: a dead connection is closed about
/// two minutes after its last traffic, a quiet live one never.
pub fn tcp_keepalive() -> TcpKeepalive {
    TcpKeepalive {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(10),
        count: 6,
        // 0 keeps the system default. A finite value would also close a connection
        // whose peer stopped reading but is alive, such as a paused player.
        #[cfg(target_os = "linux")]
        user_timeout: Duration::ZERO,
    }
}

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

/// A resolved upstream: a lowercase host name (used for SNI and `Host`) and its
/// addresses.
#[derive(Debug, Clone)]
pub struct Origin {
    pub host: String,
    pub port: u16,
    pub addrs: Arc<Addrs>,
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

    /// A peer for one connection attempt to `addr`. SNI is always set: an empty SNI
    /// would turn off certificate verification in the connector.
    pub fn peer(&self, addr: SocketAddr) -> Result<HttpPeer> {
        let mut peer = HttpPeer::new(addr, true, self.host.clone())?;
        let o = &mut peer.options;
        o.alpn = ALPN::H1;
        o.verify_cert = true;
        o.verify_hostname = true;
        o.connection_timeout = Some(self.options.connect_timeout);
        o.total_connection_timeout = Some(self.options.connect_timeout);
        o.read_timeout = Some(self.options.read_timeout);
        o.write_timeout = Some(self.options.read_timeout);
        o.idle_timeout = Some(self.options.idle_timeout);
        o.tcp_keepalive = Some(tcp_keepalive());
        Ok(peer)
    }
}
