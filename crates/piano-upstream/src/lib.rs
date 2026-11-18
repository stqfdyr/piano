//! Upstream side: resolving origins, building peers and the TLS client config.

#![forbid(unsafe_code)]

pub mod origin;
pub mod resolve;
pub mod tls;

pub use origin::{Origin, PeerOptions};
pub use resolve::Resolver;
