//! Assembles the daemon from a validated configuration.

#![forbid(unsafe_code)]

use piano_config::Config;
use piano_proxy::{Relay, Site, Sites};
use piano_upstream::{Origin, PeerOptions, Resolver};
use pingora_core::connectors::ConnectorOptions;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::ProxyServiceBuilder;
use std::sync::Arc;

pub use pingora_core::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};

/// Pingora's own pool cap is per worker; one worker per CPU on small hosts.
const UPSTREAM_POOL_SIZE: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Edge(#[from] piano_edge::tls::Error),
    #[error(transparent)]
    UpstreamTls(#[from] piano_upstream::tls::Error),
    #[error(transparent)]
    Resolve(#[from] piano_upstream::resolve::Error),
    #[error("site {site}: invalid upstream host header: {source}")]
    Site {
        site: String,
        source: http::header::InvalidHeaderValue,
    },
    #[error("site {0}: upstream was not validated")]
    Unvalidated(String),
}

/// Builds a ready-to-run server: listeners, TLS and the relay service.
pub fn build_server(config: &Config, resolver: &Resolver) -> Result<Server, Error> {
    let server_tls = piano_edge::tls::server_config(config)?;
    let client_tls = piano_upstream::tls::client_config(&config.upstream.extra_roots)?;
    let sites = Arc::new(build_sites(config, resolver)?);

    let threads = match config.server.threads {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        n => n,
    };
    let conf = ServerConf {
        threads,
        work_stealing: false,
        upstream_keepalive_pool_size: UPSTREAM_POOL_SIZE,
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

    let mut service = ProxyServiceBuilder::new(&conf, Relay::new(sites))
        .name("piano")
        .client_options(client)
        .build();
    for addr in &config.server.listen {
        let tls = TlsSettings::with_server_config(Arc::clone(&server_tls));
        service.add_tls_with_settings(addr, None, tls);
    }

    server.add_service(service);
    Ok(server)
}

fn build_sites(config: &Config, resolver: &Resolver) -> Result<Sites, Error> {
    let options = PeerOptions::from(&config.upstream);
    let mut sites = Vec::with_capacity(config.sites.len());
    for site in &config.sites {
        let url = site
            .upstream_url
            .as_ref()
            .ok_or_else(|| Error::Unvalidated(site.name.clone()))?;
        let addr = resolver.resolve_blocking(&url.host, url.port)?;
        let origin = Origin {
            host: url.host.clone(),
            port: url.port,
            addr,
            options,
        };
        let s = Site::new(site.name.clone(), site.host.clone(), origin).map_err(|source| {
            Error::Site {
                site: site.name.clone(),
                source,
            }
        })?;
        sites.push(s);
    }
    Ok(Sites::new(sites))
}
