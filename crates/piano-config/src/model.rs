use crate::{Duration, IpNet, UpstreamUrl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The whole configuration file.
#[derive(Debug, Deserialize, Serialize)]
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
    pub limits: Limits,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default)]
    pub log: Log,
    #[serde(default)]
    pub control: Control,
    #[serde(default)]
    pub cache: Cache,
    #[serde(default)]
    pub traffic: Traffic,
    #[serde(default, rename = "site")]
    pub sites: Vec<Site>,
}

/// Process-level settings; changing them needs a restart.
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Who may connect. Checked on the client address before the TLS handshake.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Access {
    /// Addresses and networks allowed to connect. Must not be empty: serving everyone
    /// has to be written out as `["0.0.0.0/0", "::/0"]`.
    pub allow: Vec<IpNet>,
}

/// Bounds on what clients may hold. The allow list keeps strangers out before TLS, so
/// these guard against a misbehaving client and keep the process within its resources.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Longest time from accepting a connection to the end of its TLS handshake.
    pub handshake_timeout: Duration,
    /// How long an idle client connection is kept open for its next request.
    pub keepalive_timeout: Duration,
    /// Most client connections open at once; further ones are closed when accepted.
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // A TLS 1.3 handshake takes one round trip; 10 s still covers three
            // consecutive losses with retransmission backing off 1, 2 and 4 s.
            handshake_timeout: Duration::from_secs(10),
            // An idle connection costs 25 to 64 KiB; a new one costs the client two round
            // trips. Clients close idle connections when they no longer want them, so the
            // relay closing them first only races their next request.
            keepalive_timeout: Duration::from_secs(600),
            // About five times the busiest moment seen on a relay (213 requests in
            // flight); 1024 idle HTTP/2 connections take about 64 MiB.
            max_connections: 1024,
        }
    }
}

/// Defaults for every upstream connection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Upstream {
    /// Longest time one attempt may take to connect, TLS handshake included, before
    /// the next address is tried.
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
            // Successful connections to CDN-fronted upstreams take under 2.3 s in 99.9%
            // of cases; slower ones are mostly lost SYNs, which a fresh attempt to the
            // next address beats.
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            extra_roots: Vec::new(),
        }
    }
}

/// Logging.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
    /// Access log file, one JSON line per request; empty turns it off. Rotate it with
    /// logrotate and SIGUSR1.
    pub access: PathBuf,
    /// Least severe diagnostic records written to stderr.
    pub level: LogLevel,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            access: PathBuf::from("/var/log/piano/access.log"),
            level: LogLevel::Info,
        }
    }
}

impl Log {
    /// The access log path, unless the access log is off.
    pub fn access_path(&self) -> Option<&std::path::Path> {
        (!self.access.as_os_str().is_empty()).then_some(self.access.as_path())
    }
}

/// The local socket the command-line tool talks to the daemon through.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Control {
    /// Unix socket path; empty turns the control socket off.
    pub socket: PathBuf,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_SOCKET),
        }
    }
}

/// Default control socket path.
pub const DEFAULT_SOCKET: &str = "/run/piano/ctl.sock";

impl Control {
    /// The socket path, unless the control socket is off.
    pub fn socket_path(&self) -> Option<&std::path::Path> {
        (!self.socket.as_os_str().is_empty()).then_some(self.socket.as_path())
    }
}

/// The image cache.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cache {
    /// Memory for image bodies, in MiB; 0 stores none. Remembered redirects and missing
    /// images are kept either way.
    pub image_memory_mib: u64,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            // Replaying two months of image requests at both relays, an LRU of 128 MB
            // serves 22–40% of them per upstream; all distinct images would take 3 GB.
            // The smallest relay has 350 MB available.
            image_memory_mib: 128,
        }
    }
}

/// Where the bytes relayed per day, site and kind are kept across restarts.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Traffic {
    /// JSON file rewritten once a minute; empty keeps no record.
    pub file: PathBuf,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            file: PathBuf::from(DEFAULT_TRAFFIC_FILE),
        }
    }
}

/// Default traffic record path.
pub const DEFAULT_TRAFFIC_FILE: &str = "/var/lib/piano/traffic.json";

impl Traffic {
    /// The record's path, unless none is kept.
    pub fn file_path(&self) -> Option<&std::path::Path> {
        (!self.file.as_os_str().is_empty()).then_some(self.file.as_path())
    }
}

/// The request limit an upstream enforces per client address, as measured.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamLimit {
    /// Requests allowed at once.
    pub burst: f64,
    /// Requests allowed per second after that.
    pub per_sec: f64,
}

/// Severity threshold of the diagnostic log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// One public host relayed to one upstream Emby server.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    /// Short name for logs and commands; defaults to the first label of `host`.
    #[serde(default)]
    pub name: String,
    pub host: String,
    pub upstream: String,
    /// Other names of the upstream server; redirects to them are followed like
    /// redirects to the upstream itself.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Limits which hosts redirects are followed to: exact names, or `*.<domain>` for
    /// exactly one more label. Empty, the default, follows any host that resolves to
    /// public addresses; the upstream decides where its media lives.
    #[serde(default)]
    pub follow: Vec<String>,
    /// Path prefixes answered with 404 instead of being relayed. Matching ignores ASCII
    /// case and an optional leading `/emby`.
    #[serde(default)]
    pub block: Vec<String>,
    /// User-Agent rewrites, tried in order; the first match wins.
    #[serde(default)]
    pub ua: Vec<UaRule>,
    /// Path prefixes relayed to another host of the upstream service, with the prefix
    /// removed: the upstream hands out URLs on such hosts, and rewriting puts them under
    /// these prefixes of the site.
    #[serde(default)]
    pub mounts: BTreeMap<String, String>,
    /// What happens to `/System/Ext/ServerDomains`, which lists names that reach the
    /// upstream directly.
    #[serde(default)]
    pub server_domains: ServerDomains,
    /// The upstream's request limit. Image requests then queue so that a quarter of it
    /// stays free for browsing and playback. Without it, image requests only hold back
    /// while the upstream asks for a pause with 429.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_limit: Option<UpstreamLimit>,
    /// Parsed form of `upstream`, filled in by validation.
    #[serde(skip)]
    pub upstream_url: Option<UpstreamUrl>,
}

/// Handling of the endpoint that lists the upstream's own domain names.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerDomains {
    /// Relayed, with the upstream's names replaced by the site's.
    #[default]
    Rewrite,
    /// Answered with 404.
    Block,
    /// Relayed unchanged.
    Pass,
}

/// Replace the User-Agent sent upstream when the client's matches `pattern`. A missing
/// User-Agent is matched as the empty string.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UaRule {
    #[serde(rename = "match")]
    pub pattern: String,
    pub set: String,
}

impl Config {
    /// The configuration as TOML with every default written out.
    pub fn effective_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// Problems that do not stop the configuration from being used.
    pub fn warnings(&self) -> Vec<crate::Warning> {
        crate::validate::warnings(self)
    }
}
