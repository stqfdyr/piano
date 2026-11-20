//! The control socket as a service of the daemon.

use crate::{Admin, RUNTIME_GROUP};
use async_trait::async_trait;
use piano_ctl::server::{self, Bound, Handler};
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use serde_json::Value;
use std::sync::Arc;

/// Serves the control socket bound at startup until shutdown begins.
pub struct ControlService {
    admin: Arc<Admin>,
    bound: Option<Bound>,
}

impl ControlService {
    /// `bound` comes from [`piano_ctl::server::bind`], called before the server runs so
    /// that a socket that cannot be created stops the start.
    pub fn new(admin: Arc<Admin>, bound: Bound) -> Self {
        Self {
            admin,
            bound: Some(bound),
        }
    }
}

struct Commands(Arc<Admin>);

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, String> {
    serde_json::to_value(v).map_err(|e| e.to_string())
}

#[async_trait]
impl Handler for Commands {
    async fn handle(&self, cmd: &str) -> Option<Result<Value, String>> {
        match cmd {
            "status" => Some(to_value(&self.0.status())),
            "reload" => Some(to_value(&self.0.reload().await)),
            "cache" => Some(to_value(&self.0.cache())),
            "live" => Some(to_value(&self.0.live_view())),
            "cache purge" => Some(to_value(&self.0.purge())),
            _ => None,
        }
    }
}

#[async_trait]
impl ServiceWithDependents for ControlService {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        ready.notify_ready();
        let Some(bound) = self.bound.take() else {
            return;
        };
        let handler = Arc::new(Commands(Arc::clone(&self.admin)));
        server::serve(bound, handler, async move {
            let _ = shutdown.changed().await;
        })
        .await;
    }

    fn name(&self) -> &str {
        "control"
    }

    fn runtime_group(&self) -> Option<&str> {
        Some(RUNTIME_GROUP)
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        Some(Vec::new())
    }
}
