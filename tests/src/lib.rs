//! Test harness: a throwaway PKI, a fake Emby origin and piano running in-process.

#![forbid(unsafe_code)]
// Test support code: failing loudly is the desired behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod client;
pub mod origin;
pub mod pki;
pub mod relay;

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// Public host every test site is served under.
pub const SITE_HOST: &str = "media.example.com";
/// Name of the fake origin; resolved to loopback through the test resolver.
pub const ORIGIN_HOST: &str = "origin.example.net";

/// A loopback port that was free a moment ago.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
