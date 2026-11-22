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
pub const CACHE_SCHEMA: u32 = 2;
/// Version of [`Live`].
pub const LIVE_SCHEMA: u32 = 1;
/// Version of [`UpgradeReply`].
pub const UPGRADE_SCHEMA: u32 = 1;
/// Version of [`StopReply`].
pub const STOP_SCHEMA: u32 = 1;

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
    /// How far back each site's `ttfb` reaches: 60 to 65 minutes once the daemon has
    /// run that long.
    #[serde(default)]
    pub ttfb_secs: u64,
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
    /// Hex sha256 of the executable the process runs, which can differ from the file
    /// now at its path.
    pub binary_sha256: Option<String>,
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
    /// The chain lacks its intermediate certificates.
    #[serde(default)]
    pub incomplete_chain: bool,
    /// Why renewed certificate files could not be loaded; the previous certificate is
    /// still served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLog {
    /// `None` when the access log is off.
    pub path: Option<String>,
    /// Lines lost since start: the disk was too slow, or writes failed.
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteStatus {
    pub name: String,
    pub host: String,
    /// `host:port` of the upstream.
    pub upstream: String,
    /// The upstream address connections currently go to; `None` while the upstream has
    /// not resolved since startup.
    pub address: Option<String>,
    #[serde(flatten)]
    pub traffic: Traffic,
    /// Time to first byte over the last `ttfb_secs`, by `browse`, `image` and
    /// `media`. Every key is present.
    #[serde(default)]
    pub ttfb: BTreeMap<String, Latency>,
}

/// Percentiles of the time to first byte.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Latency {
    pub count: u64,
    /// `None` without requests.
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
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

/// Reply to `stop`: the daemon stops as on SIGTERM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopReply {
    pub schema: u32,
    pub pid: u32,
    /// The longest the daemon waits for requests in progress, in seconds.
    pub limit_secs: u64,
    /// The process this one took over from, if it still runs: it drains media streams
    /// and stops on the same signal.
    #[serde(default)]
    pub draining_pid: Option<u32>,
}

/// Reply to `upgrade`: whether a new process took over the listening sockets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpgradeReply {
    pub schema: u32,
    pub ok: bool,
    pub error: Option<String>,
    /// Whether the new binary rejected the configuration file.
    pub config_error: bool,
    /// The new binary's `--version` line.
    pub version: Option<String>,
    pub old_pid: u32,
    pub new_pid: Option<u32>,
    /// From starting the new process until it served.
    pub ready_ms: Option<u64>,
    /// Media streams the old process keeps serving until they end.
    pub draining_streams: usize,
    /// The longest the old process keeps them, in seconds.
    pub drain_limit_secs: u64,
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
    /// Images the upstream answered 404 for, remembered for a while.
    pub missing: u64,
    /// Remembered permanent redirects.
    pub redirects: u64,
    /// How image requests were answered since start: by an upstream request of their own
    /// (`fetched`) or one they shared (`coalesced`), with a remembered 404
    /// (`missing_hits`), or with 429 because the budget did not allow a request in time
    /// (`shed`).
    pub fetched: u64,
    pub coalesced: u64,
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
    /// Image requests waiting for the budget now.
    #[serde(default)]
    pub waiting: u64,
}

/// Reply to `live`: what the daemon is doing now, for `piano top`. Counters are
/// totals since start; a reader takes two replies and divides the difference by the
/// difference of `uptime_ms`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Live {
    pub schema: u32,
    pub version: String,
    pub pid: u32,
    /// Milliseconds since start on a clock that only moves forward.
    pub uptime_ms: u64,
    pub connections: Connections,
    /// `None` when the access log is off.
    pub access_log: Option<String>,
    /// Upper bounds of the `ttfb` buckets in milliseconds; the last bucket has none.
    pub ttfb_bounds_ms: Vec<f64>,
    pub sites: Vec<SiteLive>,
    pub streams: Vec<StreamLive>,
    pub cache: CacheStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteLive {
    pub name: String,
    pub total: Counts,
    /// Bucket counts of the time to first byte since start, by `browse`, `image` and
    /// `media`. Every key is present.
    pub ttfb: BTreeMap<String, Vec<u64>>,
}

/// A media stream being relayed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamLive {
    pub rid: String,
    pub site: String,
    pub client: Option<String>,
    /// Request target, credentials removed.
    pub path: String,
    pub range: Option<String>,
    pub age_ms: u64,
    /// Body bytes written to the client.
    pub sent: u64,
    /// Offset of the next byte in the whole file, and the file's length, when known.
    pub position: Option<u64>,
    pub size: Option<u64>,
    /// `None` while the stream waits for its response head.
    pub ttfb_ms: Option<u64>,
    /// Time since bytes last reached the client (since the start before any did).
    pub idle_ms: u64,
    /// Upstream requests: all of them, those started because the body stalled, and
    /// those that replaced a failed or short one.
    pub requests: u32,
    pub hedges: u32,
    pub resumes: u32,
    /// Upstream requests in flight now.
    pub in_flight: u32,
    /// Bytes wait for the client to take them: the client, not the upstream, holds the
    /// stream (a paused player or a slow link).
    pub client_holds: bool,
    /// Host the bytes come from.
    pub upstream: Option<String>,
}

/// Reply to `cache purge`: what was removed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PurgeReply {
    pub schema: u32,
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
