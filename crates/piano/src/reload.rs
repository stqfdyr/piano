//! Signals: SIGHUP rereads the configuration, SIGUSR1 reopens the access log.

use crate::{Live, RUNTIME_GROUP};
use async_trait::async_trait;
use log::{LevelFilter, error, info, warn};
use piano_telemetry::logger;
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{Signal, SignalKind, signal};

/// Applies configuration reloads and log reopening to the running daemon, and writes
/// out the summaries of rate-limited log records.
pub struct Reloader {
    live: Arc<Live>,
    path: PathBuf,
    /// Diagnostic log level given on the command line, which the file does not override.
    level_override: Option<LevelFilter>,
}

impl Reloader {
    pub fn new(live: Arc<Live>, path: PathBuf, level_override: Option<LevelFilter>) -> Self {
        Self {
            live,
            path,
            level_override,
        }
    }

    async fn reload(&self) {
        let live = Arc::clone(&self.live);
        let path = self.path.clone();
        // Reading files and resolving new origins block.
        let result = tokio::task::spawn_blocking(move || {
            let config = piano_config::load(&path)?;
            let warnings = config.warnings();
            let level = config.log.level;
            live.apply(&config).map(|fixed| (fixed, warnings, level))
        })
        .await;
        match result {
            Ok(Ok((fixed, warnings, level))) => {
                if self.level_override.is_none() {
                    logger::set_level(crate::level_filter(level));
                }
                for w in warnings {
                    warn!("{w}");
                }
                if !fixed.is_empty() {
                    warn!("restart needed for: {}", fixed.join(", "));
                }
                info!("configuration reloaded from {}", self.path.display());
            }
            Ok(Err(e)) => warn!("reload failed, keeping the running configuration: {e}"),
            Err(e) => error!("reload task failed: {e}"),
        }
    }

    async fn reopen(&self) {
        let live = Arc::clone(&self.live);
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
        loop {
            tokio::select! {
                _ = recv(&mut hup) => self.reload().await,
                _ = recv(&mut usr1) => self.reopen().await,
                _ = tick.tick() => logger::flush_aggregated(false),
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
