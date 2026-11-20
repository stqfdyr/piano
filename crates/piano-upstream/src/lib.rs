//! Upstream side: resolving origins, building peers and the TLS client config.

#![forbid(unsafe_code)]

pub mod origin;
pub mod resolve;
pub mod tls;

pub use origin::{Origin, PeerOptions, tcp_keepalive};
pub use resolve::{AddrCache, Addrs, Resolver};
