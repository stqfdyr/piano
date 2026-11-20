//! Assembles the daemon from a validated configuration and applies reloads.

#![forbid(unsafe_code)]

mod reload;

use arc_swap::ArcSwap;
use piano_config::Config;
use piano_edge::acl::{AccessFilter, Acl};
use piano_edge::tls::{CertStore, SniRecorder, SniTable};
use piano_proxy::{MAX_ATTEMPTS, Policy, Relay, Site, SiteError, Sites};
use piano_upstream::{Origin, PeerOptions, Resolver};
use pingora_core::connectors::ConnectorOptions;
use pingora_core::listeners::TcpSocketOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::ProxyServiceBuilder;
use std::path::PathBuf;
use std::sync::Arc;

pub use pingora_core::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
pub use reload::Reloader;

/// Pingora's own pool cap is per worker; one worker per CPU on small hosts.
const UPSTREAM_POOL_SIZE: usize = 128;

/// All services share one runtime: one worker per CPU, no extra threads.
const RUNTIME_GROUP: &str = "piano";

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
}

/// A server ready to run and the handle that reconfigures it.
pub struct Daemon {
    pub server: Server,
    pub live: Arc<Live>,
}

/// The parts of a running daemon that a reload replaces.
pub struct Live {
    access: Arc<AccessFilter>,
    certs: Arc<CertStore>,
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
}

impl Fixed {
    fn of(config: &Config) -> Self {
        Self {
            listen: config.server.listen.clone(),
            threads: config.server.threads,
            shutdown_timeout: config.server.shutdown_timeout,
            extra_roots: config.upstream.extra_roots.clone(),
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
        out
    }
}

/// Builds a ready-to-run server: listeners, access control, TLS and the relay service.
pub fn build(config: &Config, resolver: Resolver) -> Result<Daemon, Error> {
    let certs = Arc::new(CertStore::new(SniTable::load(config)?));
    let server_tls = piano_edge::tls::server_config(Arc::clone(&certs))?;
    let client_tls = piano_upstream::tls::client_config(&config.upstream.extra_roots)?;
    let sites = Arc::new(ArcSwap::from_pointee(build_sites(config, &resolver, None)?));
    let access = Arc::new(AccessFilter::new(Acl::new(&config.access.allow)));

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

    let mut service =
        ProxyServiceBuilder::new(&conf, Relay::new(Arc::clone(&sites), resolver.clone()))
            .name("piano")
            .client_options(client)
            .build();
    service.set_runtime_group(RUNTIME_GROUP);
    service.set_connection_filter(Arc::clone(&access) as _);
    for addr in &config.server.listen {
        let mut tls = TlsSettings::with_server_config(Arc::clone(&server_tls));
        tls.set_callbacks(Box::new(SniRecorder));
        let mut sock = TcpSocketOptions::default();
        sock.tcp_keepalive = Some(piano_upstream::tcp_keepalive());
        service.add_tls_with_settings(addr, Some(sock), tls);
    }
    server.add_service(service);

    let live = Arc::new(Live {
        access,
        certs,
        sites,
        resolver,
        fixed: Fixed::of(config),
    });
    Ok(Daemon { server, live })
}

impl Live {
    /// Replaces certificates, the allow list and the site table with those of `config`.
    ///
    /// Everything is built before anything is swapped, so on error the running
    /// configuration is untouched. Returns the names of changed settings that only take
    /// effect after a restart.
    pub fn apply(&self, config: &Config) -> Result<Vec<&'static str>, Error> {
        let table = SniTable::load(config)?;
        let current = self.sites.load();
        let sites = build_sites(config, &self.resolver, Some(&current))?;
        let acl = Acl::new(&config.access.allow);
        self.certs.replace(table);
        self.access.replace(acl);
        self.sites.store(Arc::new(sites));
        Ok(self.fixed.changed(&Fixed::of(config)))
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
