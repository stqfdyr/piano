//! Assembles the daemon from a validated configuration and applies reloads.

#![forbid(unsafe_code)]

mod admin;
mod control;
mod procfs;
mod reload;
pub mod traffic;

use arc_swap::ArcSwap;
use piano_config::Config;
use piano_edge::acl::{AccessFilter, Acl};
use piano_edge::tls::{CertStore, SniRecorder, SniTable};
use piano_media::Streams;
use piano_proxy::{Images, MAX_ATTEMPTS, Policy, Relay, Site, SiteError, Sites, Stop};
use piano_telemetry::{AccessLog, Metrics};
use piano_upstream::{Origin, PeerOptions, Resolver};
use pingora_core::apps::HttpServerOptions;
use pingora_core::connectors::ConnectorOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::{AcceptLimits, AcceptStats, ListenerConfig, TcpSocketOptions};
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::ProxyServiceBuilder;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub use admin::Admin;
pub use control::ControlService;
pub use pingora_core::server::{
    RunArgs, ShutdownSignal, ShutdownSignalWatch, UnixShutdownSignalWatch,
};
pub use reload::Reloader;

/// Idle upstream connections kept per pool. pingora's proxy, the media engine and the
/// image engine each have an HTTP/1.1 pool; their HTTP/2 pools hold about one connection
/// per upstream address, since a connection carries many requests.
const UPSTREAM_POOL_SIZE: usize = 128;

/// Upstream pools that can fill up: the HTTP/1.1 ones.
const UPSTREAM_POOLS: u64 = 3;

/// All services share one runtime: one worker per CPU, no extra threads.
const RUNTIME_GROUP: &str = "piano";

/// Limit on each read of an HTTP/1 request head once it started arriving. A client in
/// the middle of sending a head has its data ready; like the handshake timeout, this
/// leaves room for three retransmissions.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long runtimes wait for blocking tasks once the connections are gone; a stuck
/// name lookup must not hold the exit back.
const RUNTIME_EXIT_WAIT: u64 = 1;

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

impl Error {
    /// Whether fixing the configuration or certificate files cures it, as opposed to a
    /// problem on the system (resolving an upstream, opening the access log).
    pub fn is_config(&self) -> bool {
        !matches!(self, Error::Resolve(_) | Error::AccessLog(_))
    }
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
    metrics: Arc<Metrics>,
    accept: Arc<AcceptStats>,
    streams: Arc<Streams>,
    images: Arc<Images>,
    ledger: traffic::Ledger,
    stop: Arc<Stop>,
    /// Client connections open when the shutdown's grace period last looked.
    left_open: Arc<AtomicUsize>,
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
    socket: PathBuf,
    traffic: PathBuf,
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
            socket: config.control.socket.clone(),
            traffic: config.traffic.file.clone(),
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
        if self.socket != other.socket {
            out.push("control.socket");
        }
        if self.traffic != other.traffic {
            out.push("traffic.file");
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
/// each, plus the upstream pools. Process-wide, so it belongs to the daemon's startup.
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
    let need = conns * 2 + UPSTREAM_POOLS * UPSTREAM_POOL_SIZE as u64 + RESERVED_FDS;
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
    let metrics = Arc::new(Metrics::new());
    let sites = Arc::new(ArcSwap::from_pointee(build_sites(
        config, &resolver, None, &metrics,
    )?));
    let accept = Arc::new(AcceptStats::default());
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
        grace_period_seconds: Some(shutdown_secs(config)),
        graceful_shutdown_timeout_seconds: Some(RUNTIME_EXIT_WAIT),
        pid_file: "/run/piano/piano.pid".to_owned(),
        upgrade_sock: "/run/piano/upgrade.sock".to_owned(),
        ..ServerConf::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    let conf = Arc::clone(&server.configuration);

    let mut client = ConnectorOptions::from_server_conf(&conf);
    client.rustls_client_config = Some((client_tls.config, client_tls.roots));
    let streams = Arc::new(Streams::default());
    let images = Arc::new(Images::new(image_memory(config)));
    let stop = Arc::new(Stop::default());

    let mut service = ProxyServiceBuilder::new(
        &conf,
        Relay::new(
            Arc::clone(&sites),
            resolver.clone(),
            client.clone(),
            Arc::clone(&streams),
            Arc::clone(&images),
            Arc::clone(&access_log),
            metrics.unrouted(),
        )
        .with_stop(Arc::clone(&stop)),
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
            stats: Some(Arc::clone(&accept)),
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
    let left_open = Arc::new(AtomicUsize::new(0));
    server.set_drained_check({
        let accept = Arc::clone(&accept);
        let left_open = Arc::clone(&left_open);
        move || {
            let open = accept.open_connections();
            left_open.store(open, Ordering::Relaxed);
            open == 0
        }
    });

    let (ledger, warning) = traffic::Ledger::open(config.traffic.file_path());
    if let Some(w) = warning {
        log::warn!("traffic record {w}");
    }
    let live = Arc::new(Live {
        access,
        access_log,
        certs,
        cert_source: Mutex::new(CertSource::of(config)),
        sites,
        resolver,
        fixed: Fixed::of(config),
        metrics,
        accept,
        streams,
        images,
        ledger,
        stop,
        left_open,
    });
    Ok(Daemon { server, live })
}

/// The longest wait for open requests after a terminate signal, in whole seconds.
fn shutdown_secs(config: &Config) -> u64 {
    let ms = config.server.shutdown_timeout.get().as_millis();
    u64::try_from(ms.div_ceil(1000)).unwrap_or(u64::MAX)
}

/// Passes on the shutdown signals of `inner`; on terminate, first ends the work that
/// would otherwise hold the shutdown back for its whole timeout.
struct Signals {
    inner: Box<dyn ShutdownSignalWatch + Send + Sync>,
    live: Arc<Live>,
}

#[async_trait::async_trait]
impl ShutdownSignalWatch for Signals {
    async fn recv(&self) -> ShutdownSignal {
        let signal = self.inner.recv().await;
        if matches!(signal, ShutdownSignal::GracefulTerminate) {
            self.live.stop.terminate();
            log::info!(
                "stopping: {} client connections open, waiting up to {}s for their requests",
                self.live.accept.open_connections(),
                self.live.fixed.shutdown_timeout.get().as_secs_f64(),
            );
        }
        signal
    }
}

/// Bytes of image bodies the configuration allows.
fn image_memory(config: &Config) -> usize {
    usize::try_from(config.cache.image_memory_mib.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
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
        let sites = build_sites(config, &self.resolver, Some(&current), &self.metrics)?;
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
        self.images.set_capacity(image_memory(config));
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

    /// The shutdown signal source for [`pingora_core::server::Server::run`]: `inner`'s
    /// signals, with media streams ended on terminate.
    pub fn signals(
        self: &Arc<Self>,
        inner: Box<dyn ShutdownSignalWatch + Send + Sync>,
    ) -> Box<dyn ShutdownSignalWatch> {
        Box::new(Signals {
            inner,
            live: Arc::clone(self),
        })
    }

    /// Call once the server has stopped: reports connections cut at the shutdown
    /// timeout, then writes the traffic record and the access log.
    pub fn stopped(&self) {
        let cut = self.left_open.swap(0, Ordering::Relaxed);
        if cut > 0 {
            log::warn!(
                "stopped with {cut} client connections still open after {}s; they were cut",
                self.fixed.shutdown_timeout.get().as_secs_f64()
            );
        }
        self.record_traffic();
        self.flush_access_log();
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

    /// Adds the bytes relayed since the last call to today's entry of the traffic record
    /// and writes the record; call once a minute and once more when stopping. Logs when
    /// writing starts or stops failing.
    pub fn record_traffic(&self) {
        let today = chrono::Local::now().date_naive();
        self.ledger.add(&self.metrics.totals(), today);
        let before = self.ledger.error();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        match self.ledger.save(now) {
            Ok(_) if before.is_some() => log::info!("traffic record written again"),
            Ok(_) => {}
            Err(e) if before.is_none() => {
                log::warn!("cannot write the traffic record, retrying every minute: {e}");
            }
            Err(_) => {}
        }
    }

    /// The traffic record's file and why writing it fails, if it does.
    pub fn traffic_state(&self) -> (Option<&Path>, Option<String>) {
        (self.ledger.path(), self.ledger.error())
    }

    /// Request counters; snapshot them once a minute with [`Metrics::tick`].
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

/// Builds the site table. An origin already in `current` keeps its addresses and the
/// one in use, so a reload does not move its pooled connections to a new bucket.
fn build_sites(
    config: &Config,
    resolver: &Resolver,
    current: Option<&Sites>,
    metrics: &Metrics,
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
        let mut options = options;
        if let Some(h2) = site.h2 {
            options.h2 = h2;
        }
        let origin = Origin {
            host: url.host.clone(),
            port: url.port,
            addrs,
            options,
        };
        let s = Policy::from_config(site)
            .and_then(|policy| {
                Site::new(
                    site.name.clone(),
                    site.host.clone(),
                    origin,
                    policy,
                    metrics.site(&site.name),
                )
            })
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
