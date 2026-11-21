//! Test harness: a throwaway PKI, a fake Emby origin and piano running in-process.

#![forbid(unsafe_code)]
// Test support code: failing loudly is the desired behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod client;
pub mod origin;
pub mod pki;
pub mod relay;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Public host every test site is served under.
pub const SITE_HOST: &str = "media.example.com";
/// Name of the fake origin; resolved to loopback through the test resolver.
pub const ORIGIN_HOST: &str = "origin.example.net";

/// A loopback port kept for its owner. On Linux (with `net.ipv4.ip_autobind_reuse` at its
/// default 0), while this lives the port goes to no other bind to port 0 and no outgoing
/// connection, so it cannot go to another test before the relay binds it; a listener that
/// sets SO_REUSEADDR, as pingora's do, can still bind and listen on it because the
/// reserving socket never listens. Other systems would need SO_REUSEPORT on both sides.
pub struct ReservedPort {
    _socket: tokio::net::TcpSocket,
    pub port: u16,
}

impl ReservedPort {
    pub fn new() -> Self {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(loopback(0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        Self {
            _socket: socket,
            port,
        }
    }
}

impl Default for ReservedPort {
    fn default() -> Self {
        Self::new()
    }
}

pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A fresh directory under the system temp dir, removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "piano-e2e-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }

    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
