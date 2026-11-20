//! Signals: SIGHUP rereads the configuration, SIGUSR1 reopens the access log. Also
//! picks up renewed certificate files.

use crate::{Admin, RUNTIME_GROUP};
use async_trait::async_trait;
use log::{error, info, warn};
use piano_telemetry::logger;
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{Signal, SignalKind, signal};

/// How often the certificate files are checked for a renewal. Certificates are renewed
/// weeks before they expire, so an hour's delay costs nothing, and checking needs no
/// hook in the renewal tool.
const CERT_CHECK_EVERY: Duration = Duration::from_secs(3600);

/// Applies configuration reloads and log reopening to the running daemon, picks up
/// renewed certificates, snapshots the request counters and writes out the summaries of
/// rate-limited log records.
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
        let mut certs = tokio::time::interval(CERT_CHECK_EVERY);
        loop {
            tokio::select! {
                _ = recv(&mut hup) => {
                    self.admin.reload().await;
                }
                _ = recv(&mut usr1) => self.reopen().await,
                _ = tick.tick() => {
                    logger::flush_aggregated(false);
                    self.admin.live().metrics().tick();
                }
                _ = certs.tick() => self.refresh_certs().await,
                _ = shutdown.changed() => break,
            }
        }
        logger::flush_aggregated(true);
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
