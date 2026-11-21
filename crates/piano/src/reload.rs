//! Signals: SIGHUP rereads the configuration, SIGUSR1 reopens the access log. Also
//! picks up renewed certificate files and moved upstream addresses.

use crate::{Admin, RUNTIME_GROUP};
use async_trait::async_trait;
use log::{error, info, warn};
use piano_telemetry::logger;
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

/// How often the certificate files are checked for a renewal. Certificates are renewed
/// weeks before they expire, so an hour's delay costs nothing, and checking needs no
/// hook in the renewal tool.
const CERT_CHECK_EVERY: Duration = Duration::from_secs(3600);

/// How often the upstreams are looked up again: the 300 s TTL usual for CDN-fronted
/// hosts. A dead address is skipped anyway, so this only bounds how long a move goes
/// unnoticed.
const ORIGIN_REFRESH_EVERY: Duration = Duration::from_secs(300);

/// Applies configuration reloads and log reopening to the running daemon, picks up
/// renewed certificates, snapshots the request counters, writes the traffic record and
/// writes out the summaries of rate-limited log records. Once the server stops, only the
/// last two go on.
pub struct Reloader {
    admin: Arc<Admin>,
}

impl Reloader {
    pub fn new(admin: Arc<Admin>) -> Self {
        Self { admin }
    }

    async fn refresh_certs(&self) {
        let live = Arc::clone(self.admin.live());
        match tokio::task::spawn_blocking(move || live.refresh_certs()).await {
            Ok(Ok(true)) => info!("certificate files changed; certificate reloaded"),
            Ok(Ok(false)) => {}
            Ok(Err(e)) => warn!(
                "certificate files changed but cannot be loaded, keeping the current certificate: {e}"
            ),
            Err(e) => error!("certificate check task failed: {e}"),
        }
    }

    /// Starts looking the upstreams up again unless the previous round still runs. Not
    /// awaited: a slow resolver must not hold up signals and the minute tick.
    fn refresh_origins(&self, running: &mut Option<JoinHandle<()>>) {
        if running.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        let live = Arc::clone(self.admin.live());
        *running = Some(tokio::task::spawn_blocking(move || live.refresh_origins()));
    }

    async fn record_traffic(&self) {
        let live = Arc::clone(self.admin.live());
        if let Err(e) = tokio::task::spawn_blocking(move || live.record_traffic()).await {
            error!("traffic record task failed: {e}");
        }
    }

    async fn reopen(&self) {
        let live = Arc::clone(self.admin.live());
        match tokio::task::spawn_blocking(move || live.reopen_access_log()).await {
            Ok(Ok(())) => info!("access log reopened"),
            Ok(Err(e)) => error!("cannot reopen the access log, still writing the old file: {e}"),
            Err(e) => error!("reopen task failed: {e}"),
        }
    }
}

fn listen(kind: SignalKind, name: &str) -> Option<Signal> {
    match signal(kind) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("cannot handle {name}: {e}");
            None
        }
    }
}

async fn recv(s: &mut Option<Signal>) {
    match s {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending().await,
    }
}

#[async_trait]
impl ServiceWithDependents for Reloader {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        ready.notify_ready();
        let mut hup = listen(SignalKind::hangup(), "SIGHUP, reload is unavailable");
        let mut usr1 = listen(
            SignalKind::user_defined1(),
            "SIGUSR1, the access log cannot be reopened",
        );
        let mut tick = tokio::time::interval(logger::WINDOW);
        // A late tick is not made up for: back-to-back snapshots would record near-empty
        // windows.
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut certs = tokio::time::interval(CERT_CHECK_EVERY);
        // The upstreams were just looked up at startup.
        let mut origins = tokio::time::interval_at(
            tokio::time::Instant::now() + ORIGIN_REFRESH_EVERY,
            ORIGIN_REFRESH_EVERY,
        );
        let mut refreshing = None;
        loop {
            tokio::select! {
                _ = recv(&mut hup) => {
                    self.admin.reload().await;
                }
                _ = recv(&mut usr1) => self.reopen().await,
                _ = tick.tick() => {
                    logger::flush_aggregated(false);
                    self.admin.live().metrics().tick();
                    self.record_traffic().await;
                }
                _ = certs.tick() => self.refresh_certs().await,
                _ = origins.tick() => self.refresh_origins(&mut refreshing),
                _ = shutdown.changed() => break,
            }
        }
        // After an upgrade this process may serve streams for up to drain_timeout, so their
        // traffic is written now and each minute until the runtime ends; Live::stopped
        // writes the rest.
        loop {
            logger::flush_aggregated(false);
            self.record_traffic().await;
            tick.tick().await;
        }
    }

    fn name(&self) -> &str {
        "reload"
    }

    fn runtime_group(&self) -> Option<&str> {
        Some(RUNTIME_GROUP)
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        Some(Vec::new())
    }
}
