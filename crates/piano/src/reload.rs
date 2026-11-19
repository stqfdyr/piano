//! Reloading the configuration file on SIGHUP.

use crate::{Live, RUNTIME_GROUP};
use async_trait::async_trait;
use log::{error, info, warn};
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};

/// Rereads the configuration file on SIGHUP and applies it to the running daemon.
pub struct Reloader {
    live: Arc<Live>,
    path: PathBuf,
}

impl Reloader {
    pub fn new(live: Arc<Live>, path: PathBuf) -> Self {
        Self { live, path }
    }

    async fn reload(&self) {
        let live = Arc::clone(&self.live);
        let path = self.path.clone();
        // Reading files and resolving new origins block.
        let result = tokio::task::spawn_blocking(move || {
            let config = piano_config::load(&path)?;
            let warnings = config.warnings();
            live.apply(&config).map(|fixed| (fixed, warnings))
        })
        .await;
        match result {
            Ok(Ok((fixed, warnings))) => {
                for w in warnings {
                    warn!("{w}");
                }
                if !fixed.is_empty() {
                    warn!("restart needed for: {}", fixed.join(", "));
                }
                info!("configuration reloaded from {}", self.path.display());
            }
            Ok(Err(e)) => error!("reload failed, keeping the running configuration: {e}"),
            Err(e) => error!("reload task failed: {e}"),
        }
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
        let mut hup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot handle SIGHUP, reload is unavailable: {e}");
                return;
            }
        };
        loop {
            tokio::select! {
                _ = hup.recv() => self.reload().await,
                _ = shutdown.changed() => break,
            }
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
