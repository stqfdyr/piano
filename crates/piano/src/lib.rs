//! Assembles the daemon from a validated configuration and applies reloads.

#![forbid(unsafe_code)]

mod reload;

use arc_swap::ArcSwap;
use piano_config::Config;
use piano_edge::acl::{AccessFilter, Acl};
use piano_edge::tls::{CertStore, SniRecorder, SniTable};
use piano_proxy::{MAX_ATTEMPTS, Policy, Relay, Site, SiteError, Sites};
use piano_telemetry::AccessLog;
use piano_upstream::{Origin, PeerOptions, Resolver};
use pingora_core::apps::HttpServerOptions;
use pingora_core::connectors::ConnectorOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::{AcceptLimits, ListenerConfig, TcpSocketOptions};
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::ProxyServiceBuilder;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub use pingora_core::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
pub use reload::Reloader;

/// Pingora's own pool cap is per worker; one worker per CPU on small hosts.
const UPSTREAM_POOL_SIZE: usize = 128;

/// All services share one runtime: one worker per CPU, no extra threads.
const RUNTIME_GROUP: &str = "piano";

/// Limit on each read of an HTTP/1 request head once it started arriving. A client in
/// the middle of sending a head has its data ready; like the handshake timeout, this
/// leaves room for three retransmissions.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// File descriptors kept for everything but client and upstream connections: listeners,
/// log files, the resolver, the signal and timer machinery.
const RESERVED_FDS: u64 = 64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] piano_config::Error),
    #[error(transparent)]
    Edge(#[from] piano_edge::tls::Error),
    #[error(transparent)]
    UpstreamTls(#[from] piano_upstream::tls::Error),
    #[error(transparent)]
    Resolve(#[from] piano_upstream::resolve::Error),
    #[error("site {site}: {source}")]
    Site { site: String, source: SiteError },
    #[error("site {0}: upstream was not validated")]
    Unvalidated(String),
    #[error("access log: {0}")]
    AccessLog(std::io::Error),
}

/// The certificate files in use and what they looked like when loaded, to notice when
/// they are renewed.
#[derive(Debug)]
struct CertSource {
    cert: PathBuf,
    key: PathBuf,
    hosts: Vec<String>,
    stamp: [Option<(SystemTime, u64)>; 2],
}

impl CertSource {
    fn of(config: &Config) -> Self {
        let mut s = Self {
            cert: config.tls.cert.clone(),
            key: config.tls.key.clone(),
            hosts: config.sites.iter().map(|s| s.host.clone()).collect(),
            stamp: [None, None],
        };
        s.stamp = s.current_stamp();
        s
    }

    fn current_stamp(&self) -> [Option<(SystemTime, u64)>; 2] {
        let stamp = |p: &Path| {
            let m = std::fs::metadata(p).ok()?;
            Some((m.modified().ok()?, m.len()))
        };
        [stamp(&self.cert), stamp(&self.key)]
    }

    fn load(&self) -> Result<SniTable, piano_edge::tls::Error> {
        let hosts: Vec<&str> = self.hosts.iter().map(String::as_str).collect();
        SniTable::from_files(&self.cert, &self.key, &hosts)
    }
}

/// A server ready to run and the handle that reconfigures it.
pub struct Daemon {
    pub server: Server,
    pub live: Arc<Live>,
}

/// The parts of a running daemon that a reload replaces.
pub struct Live {
    access: Arc<AccessFilter>,
    access_log: Arc<AccessLog>,
    certs: Arc<CertStore>,
    cert_source: Mutex<CertSource>,
    sites: Arc<ArcSwap<Sites>>,
    resolver: Resolver,
    fixed: Fixed,
}

/// Settings read once at startup; a reload that changes them only warns.
#[derive(PartialEq)]
struct Fixed {
    listen: Vec<String>,
    threads: usize,
    shutdown_timeout: piano_config::Duration,
    extra_roots: Vec<PathBuf>,
    handshake_timeout: piano_config::Duration,
    keepalive_timeout: piano_config::Duration,
    max_connections: usize,
}

impl Fixed {
    fn of(config: &Config) -> Self {
        Self {
            listen: config.server.listen.clone(),
            threads: config.server.threads,
            shutdown_timeout: config.server.shutdown_timeout,
            extra_roots: config.upstream.extra_roots.clone(),
            handshake_timeout: config.limits.handshake_timeout,
            keepalive_timeout: config.limits.keepalive_timeout,
            max_connections: config.limits.max_connections,
        }
    }

    /// Names of the settings that differ.
    fn changed(&self, other: &Self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.listen != other.listen {
            out.push("server.listen");
        }
        if self.threads != other.threads {
            out.push("server.threads");
        }
        if self.shutdown_timeout != other.shutdown_timeout {
            out.push("server.shutdown_timeout");
        }
        if self.extra_roots != other.extra_roots {
            out.push("upstream.extra_roots");
        }
        if self.handshake_timeout != other.handshake_timeout {
            out.push("limits.handshake_timeout");
        }
        if self.keepalive_timeout != other.keepalive_timeout {
            out.push("limits.keepalive_timeout");
        }
        if self.max_connections != other.max_connections {
            out.push("limits.max_connections");
        }
        out
    }
}

/// The diagnostic log threshold for a configured level.
pub fn level_filter(level: piano_config::LogLevel) -> log::LevelFilter {
    piano_telemetry::logger::parse_level(level.as_str()).unwrap_or(log::LevelFilter::Info)
}

/// Raises the soft limit on open files to the hard limit, and warns when even that
/// cannot hold `limits.max_connections` client connections with one upstream connection
/// each, plus the upstream pool. Process-wide, so it belongs to the daemon's startup.
pub fn raise_open_file_limit(config: &Config) {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("cannot read the open file limit: {e}");
            return;
        }
    };
    let mut limit = soft;
    if soft < hard {
        match setrlimit(Resource::RLIMIT_NOFILE, hard, hard) {
            Ok(()) => limit = hard,
            Err(e) => log::warn!("cannot raise the open file limit from {soft} to {hard}: {e}"),
        }
    }
    let conns = config.limits.max_connections as u64 * config.server.listen.len() as u64;
    let need = conns * 2 + UPSTREAM_POOL_SIZE as u64 + RESERVED_FDS;
    if limit < need {
        log::warn!(
            "open file limit {limit} is below the {need} that limits.max_connections = {} \
             may need; raise LimitNOFILE (systemd) or rc_ulimit (OpenRC)",
            config.limits.max_connections
        );
    }
}

/// Builds a ready-to-run server: listeners, access control, TLS and the relay service.
pub fn build(config: &Config, resolver: Resolver) -> Result<Daemon, Error> {
    let certs = Arc::new(CertStore::new(SniTable::load(config)?));
    let server_tls = piano_edge::tls::server_config(Arc::clone(&certs))?;
    let client_tls = piano_upstream::tls::client_config(&config.upstream.extra_roots)?;
    let sites = Arc::new(ArcSwap::from_pointee(build_sites(config, &resolver, None)?));
    let access = Arc::new(AccessFilter::new(Acl::new(&config.access.allow)));
    let access_log = Arc::new(AccessLog::open(config.log.access_path()).map_err(Error::AccessLog)?);

    let threads = match config.server.threads {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        n => n,
    };
    let conf = ServerConf {
        threads,
        work_stealing: false,
        upstream_keepalive_pool_size: UPSTREAM_POOL_SIZE,
        max_retries: MAX_ATTEMPTS,
        grace_period_seconds: Some(0),
        graceful_shutdown_timeout_seconds: Some(config.server.shutdown_timeout.get().as_secs()),
        pid_file: "/run/piano/piano.pid".to_owned(),
        upgrade_sock: "/run/piano/upgrade.sock".to_owned(),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    let conf = Arc::clone(&server.configuration);

    let mut client = ConnectorOptions::from_server_conf(&conf);
    client.rustls_client_config = Some((client_tls.config, client_tls.roots));

    let mut service = ProxyServiceBuilder::new(
        &conf,
        Relay::new(
            Arc::clone(&sites),
            resolver.clone(),
            Arc::clone(&access_log),
        ),
    )
    .name("piano")
    .client_options(client)
    .server_options(server_options(config))
    .build();
    service.set_runtime_group(RUNTIME_GROUP);
    service.set_connection_filter(Arc::clone(&access) as _);
    for addr in &config.server.listen {
        let mut tls = TlsSettings::with_server_config(Arc::clone(&server_tls));
        tls.set_callbacks(Box::new(SniRecorder));
        let mut sock = TcpSocketOptions::default();
        sock.tcp_keepalive = Some(piano_upstream::tcp_keepalive());
        let limits = AcceptLimits {
            handshake_timeout: config.limits.handshake_timeout.get(),
            max_connections: Some(config.limits.max_connections),
            ..AcceptLimits::default()
        };
        service.add_listener(
            ListenerConfig::tcp(addr.as_str())
                .tcp_socket_options(sock)
                .tls(tls)
                .accept_limits(limits),
        );
    }
    server.add_service(service);

    let live = Arc::new(Live {
        access,
        access_log,
        certs,
        cert_source: Mutex::new(CertSource::of(config)),
        sites,
        resolver,
        fixed: Fixed::of(config),
    });
    Ok(Daemon { server, live })
}

/// How client connections are kept between requests.
fn server_options(config: &Config) -> HttpServerOptions {
    let keepalive = config.limits.keepalive_timeout.get();
    let mut o = HttpServerOptions::default();
    o.h1_keepalive_timeout = Some(keepalive);
    o.h1_header_read_timeout = Some(HEADER_READ_TIMEOUT);
    o.h2_idle_timeout = Some(keepalive);
    o
}

impl Live {
    /// Replaces certificates, the allow list and the site table with those of `config`.
    ///
    /// Everything is built before anything is swapped, so on error the running
    /// configuration is untouched. Returns the names of changed settings that only take
    /// effect after a restart.
    pub fn apply(&self, config: &Config) -> Result<Vec<&'static str>, Error> {
        let source = CertSource::of(config);
        let table = source.load()?;
        let current = self.sites.load();
        let sites = build_sites(config, &self.resolver, Some(&current))?;
        let acl = Acl::new(&config.access.allow);
        // Opens the new file, if any, before anything is replaced; the last step that can
        // fail.
        self.access_log
            .set_path(config.log.access_path())
            .map_err(Error::AccessLog)?;
        self.certs.replace(table);
        *self
            .cert_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
        self.access.replace(acl);
        self.sites.store(Arc::new(sites));
        Ok(self.fixed.changed(&Fixed::of(config)))
    }

    /// Reloads the certificate if its files changed since they were loaded. Returns
    /// whether it was replaced; on error the current one stays and the next call tries
    /// again.
    pub fn refresh_certs(&self) -> Result<bool, Error> {
        let mut source = self
            .cert_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stamp = source.current_stamp();
        if stamp == source.stamp {
            return Ok(false);
        }
        let table = source.load()?;
        self.certs.replace(table);
        source.stamp = stamp;
        Ok(true)
    }

    /// Starts a new access log file at the same path, after logrotate moved the old one.
    pub fn reopen_access_log(&self) -> std::io::Result<()> {
        self.access_log.reopen()
    }

    /// Waits until the access log lines queued so far are written.
    pub fn flush_access_log(&self) {
        self.access_log.flush();
    }

    /// Access log lines lost because the disk could not keep up.
    pub fn dropped_access_lines(&self) -> u64 {
        self.access_log.dropped()
    }

    /// Connections refused by the allow list since start.
    pub fn denied_connections(&self) -> u64 {
        self.access.denied()
    }
}

/// Builds the site table. An origin already in `current` keeps its addresses and the
/// one in use, so a reload does not move its pooled connections to a new bucket.
fn build_sites(
    config: &Config,
    resolver: &Resolver,
    current: Option<&Sites>,
) -> Result<Sites, Error> {
    let options = PeerOptions::from(&config.upstream);
    let mut sites = Vec::with_capacity(config.sites.len());
    for site in &config.sites {
        let url = site
            .upstream_url
            .as_ref()
            .ok_or_else(|| Error::Unvalidated(site.name.clone()))?;
        let known = current.and_then(|c| {
            c.iter()
                .map(|s| &s.origin)
                .find(|o| o.host == url.host && o.port == url.port)
                .map(|o| Arc::clone(&o.addrs))
        });
        let addrs = match known {
            Some(a) => a,
            None => Arc::new(resolver.resolve_blocking(&url.host, url.port)?),
        };
        let origin = Origin {
            host: url.host.clone(),
            port: url.port,
            addrs,
            options,
        };
        let s = Policy::from_config(site)
            .and_then(|policy| Site::new(site.name.clone(), site.host.clone(), origin, policy))
            .map_err(|source| Error::Site {
                site: site.name.clone(),
                source,
            })?;
        sites.push(s);
    }
    Ok(Sites::new(sites))
}

#[cfg(test)]
mod tests {
    #[test]
    fn handshake_target_matches_the_fork() {
        assert_eq!(
            piano_telemetry::logger::HANDSHAKE,
            pingora_core::listeners::HANDSHAKE_LOG_TARGET
        );
    }
}
