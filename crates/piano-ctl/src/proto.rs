//! Messages and the data the commands return. Field names are stable: the CLI prints
//! them with `--json` for scripts and agents; a change that is not an addition bumps
//! the `schema` of the reply it belongs to.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    pub cmd: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn data(data: Value) -> Self {
        Self {
            v: crate::PROTOCOL_VERSION,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            v: crate::PROTOCOL_VERSION,
            ok: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

/// Version of [`Status`].
pub const STATUS_SCHEMA: u32 = 1;
/// Version of [`ReloadReply`].
pub const RELOAD_SCHEMA: u32 = 1;
/// Version of [`CacheStats`] and [`PurgeReply`].
pub const CACHE_SCHEMA: u32 = 1;

/// Reply to `status`. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub schema: u32,
    pub version: String,
    pub pid: u32,
    pub started: u64,
    pub uptime_secs: u64,
    pub config: ConfigState,
    pub process: Process,
    pub connections: Connections,
    pub certificate: Certificate,
    pub access_log: AccessLog,
    /// How far back each `recent` count reaches: an hour once the daemon has run that
    /// long.
    pub recent_secs: u64,
    pub sites: Vec<SiteStatus>,
    /// Requests whose host is no site.
    pub unrouted: Traffic,
    /// Problems worth acting on, most severe first.
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigState {
    pub path: String,
    /// When the configuration in use was loaded.
    pub loaded: u64,
    pub last_reload: Option<ReloadRecord>,
    /// Settings changed in the file since start that only a restart applies.
    pub restart_needed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReloadRecord {
    pub at: u64,
    pub ok: bool,
    pub error: Option<String>,
}

/// Read from `/proc`; `None` where it could not be.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Process {
    pub rss_bytes: Option<u64>,
    pub threads: Option<u64>,
    pub open_files: Option<u64>,
    pub max_open_files: Option<u64>,
}

/// Client connections, over all listening addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Connections {
    pub open: u64,
    pub handshaking: u64,
    /// `limits.max_connections` times the number of listening addresses.
    pub limit: u64,
    /// The counts below are since start.
    pub closed_at_limit: u64,
    pub handshake_timeouts: u64,
    pub handshake_errors: u64,
    /// Refused by the allow list.
    pub denied: u64,
    /// Media streams being relayed now.
    #[serde(default)]
    pub media_streams: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    pub names: Vec<String>,
    pub not_after: Option<i64>,
    pub loaded: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLog {
    /// `None` when the access log is off.
    pub path: Option<String>,
    /// Lines lost since start because the disk could not keep up.
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteStatus {
    pub name: String,
    pub host: String,
    /// `host:port` of the upstream.
    pub upstream: String,
    /// The upstream address connections currently go to.
    pub address: String,
    #[serde(flatten)]
    pub traffic: Traffic,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Traffic {
    /// Since start.
    pub total: Counts,
    /// Over the last `recent_secs`.
    pub recent: Counts,
}

/// Finished requests.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Counts {
    pub requests: u64,
    /// By status class sent to the client: `1xx` … `5xx`, and `none` when no response
    /// was sent. Every class is present.
    pub status: BTreeMap<String, u64>,
    /// By how the request ended, as the access log's `end`. Every value is present.
    pub ends: BTreeMap<String, u64>,
    /// Upstream attempts; redirects followed and connection retries each add one.
    pub upstream_attempts: u64,
    /// Attempts that reused a pooled connection.
    pub reused: u64,
    /// Response body bytes written to clients.
    #[serde(default)]
    pub bytes_sent: u64,
    /// Response body bytes read from upstreams, retried and hedged requests included.
    #[serde(default)]
    pub bytes_fetched: u64,
}

impl Counts {
    pub fn status(&self, class: &str) -> u64 {
        self.status.get(class).copied().unwrap_or(0)
    }

    pub fn end(&self, end: &str) -> u64 {
        self.ends.get(end).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Warn,
    Error,
}

/// Something in the status that needs attention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub level: Level,
    /// Stable identifier, e.g. `cert_expiring`.
    pub code: String,
    pub message: String,
    /// What to do or look at next.
    pub hint: Option<String>,
}

/// Reply to `reload`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReloadReply {
    pub schema: u32,
    pub ok: bool,
    pub error: Option<String>,
    /// Whether the failure is in the configuration or certificate files, as opposed to
    /// the system (resolving a new upstream, opening the access log).
    pub config_error: bool,
    pub restart_needed: Vec<String>,
    pub warnings: Vec<String>,
}

/// Reply to `cache`: the image engine since start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheStats {
    pub schema: u32,
    /// Image bodies held, their bytes and the memory allowed for them.
    pub images: u64,
    pub bytes: u64,
    pub capacity: u64,
    /// Images the upstream answered 404 for, remembered for a while.
    pub missing: u64,
    /// Remembered permanent redirects.
    pub redirects: u64,
    /// How image requests were answered since start: from memory (`hits`), by an
    /// upstream request of their own (`misses`) or one they shared (`coalesced`), from an
    /// expired copy because the upstream failed (`stale`), after the upstream confirmed
    /// the copy (`revalidated`), with a remembered 404 (`missing_hits`), or with 429
    /// because the budget did not allow a request in time (`shed`).
    pub hits: u64,
    pub misses: u64,
    pub coalesced: u64,
    pub stale: u64,
    pub revalidated: u64,
    pub missing_hits: u64,
    pub shed: u64,
    /// Upstream requests that went straight to a remembered redirect target.
    pub redirect_hits: u64,
    pub upstreams: Vec<UpstreamBudget>,
}

/// The request budget of one upstream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamBudget {
    /// `host:port`.
    pub upstream: String,
    /// The configured limit; `None` when only 429 pauses apply.
    pub burst: Option<f64>,
    pub per_sec: Option<f64>,
    /// Requests the budget allows now.
    pub tokens: f64,
    /// Seconds left of a pause the upstream asked for.
    pub paused_secs: Option<f64>,
    /// Upstream 429 answers since start.
    pub limited: u64,
}

/// Reply to `cache purge`: what was removed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurgeReply {
    pub schema: u32,
    pub images: u64,
    pub missing: u64,
    pub redirects: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes() {
        let req: Request = serde_json::from_str(r#"{"v":1,"cmd":"status"}"#).unwrap();
        assert_eq!(req.cmd, "status");
        assert_eq!(
            serde_json::to_string(&Response::error("nope")).unwrap(),
            r#"{"v":1,"ok":false,"error":"nope"}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::data(Value::Bool(true))).unwrap(),
            r#"{"v":1,"ok":true,"data":true}"#
        );
    }
}
