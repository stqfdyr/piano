use crate::{Duration, IpNet, UpstreamUrl};
use serde::Deserialize;
use std::path::PathBuf;

/// The whole configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub server: Server,
    pub tls: Tls,
    #[serde(default)]
    pub access: Access,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default, rename = "site")]
    pub sites: Vec<Site>,
}

/// Process-level settings; changing them needs a restart.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Server {
    pub listen: Vec<String>,
    /// Worker threads; 0 means one per CPU.
    pub threads: usize,
    pub shutdown_timeout: Duration,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: vec!["[::]:443".to_owned()],
            threads: 0,
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// The downstream certificate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Who may connect. Checked on the client address before the TLS handshake.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Access {
    /// Addresses and networks allowed to connect. Must not be empty: serving everyone
    /// has to be written out as `["0.0.0.0/0", "::/0"]`.
    pub allow: Vec<IpNet>,
}

/// Defaults for every upstream connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upstream {
    pub connect_timeout: Duration,
    /// Longest gap between two reads; detects stalled streams.
    pub read_timeout: Duration,
    /// Longest time an idle connection stays pooled.
    pub idle_timeout: Duration,
    /// Extra trust anchors, added to the system roots.
    pub extra_roots: Vec<PathBuf>,
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            extra_roots: Vec::new(),
        }
    }
}

/// One public host relayed to one upstream Emby server.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Short name for logs and commands; defaults to the first label of `host`.
    #[serde(default)]
    pub name: String,
    pub host: String,
    pub upstream: String,
    /// Path prefixes answered with 404 instead of being relayed. Matching ignores ASCII
    /// case and an optional leading `/emby`.
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub cookies: Cookies,
    /// User-Agent rewrites, tried in order; the first match wins.
    #[serde(default)]
    pub ua: Vec<UaRule>,
    /// Parsed form of `upstream`, filled in by validation.
    #[serde(skip)]
    pub upstream_url: Option<UpstreamUrl>,
}

/// Cookie handling towards the upstream.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cookies {
    /// Cookie names removed from requests.
    pub strip: Vec<String>,
}

/// Replace the User-Agent sent upstream when the client's matches `pattern`. A missing
/// User-Agent is matched as the empty string.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UaRule {
    #[serde(rename = "match")]
    pub pattern: String,
    pub set: String,
}

impl Config {
    /// Problems that do not stop the configuration from being used.
    pub fn warnings(&self) -> Vec<crate::Warning> {
        crate::validate::warnings(self)
    }
}
