//! Reloading and reporting status, shared by the signal handler and the control socket.

use crate::{Live, procfs};
use log::{LevelFilter, error, info, warn};
use piano_ctl::proto::{
    self, CACHE_SCHEMA, CacheStats, Certificate, ConfigState, Connections, Finding, LIVE_SCHEMA,
    Latency, Level, PurgeReply, RELOAD_SCHEMA, ReloadRecord, ReloadReply, STATUS_SCHEMA, SiteLive,
    SiteStatus, Status, StreamLive, Traffic, UpstreamBudget,
};
use piano_telemetry::Ttfb;
use piano_telemetry::latency::{self, BOUNDS_US, Buckets};
use piano_telemetry::logger;
use piano_telemetry::metrics::{Counts, End, STATUS_CLASSES, TtfbBuckets};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Certificates are renewed 30 days before they expire; 14 days left means renewal has
/// been failing for two weeks.
const CERT_WARN_DAYS: i64 = 14;
/// Few enough days left that clients will soon refuse the certificate.
const CERT_ERROR_DAYS: i64 = 3;
/// Share of a limit in use from which status warns.
const NEAR_LIMIT_PERCENT: u64 = 80;

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[derive(Debug)]
struct State {
    loaded: SystemTime,
    last_reload: Option<ReloadRecord>,
    restart_needed: Vec<&'static str>,
}

/// Applies reloads and reports status for a running daemon.
pub struct Admin {
    live: Arc<Live>,
    path: PathBuf,
    /// Diagnostic log level given on the command line, which the file does not override.
    level_override: Option<LevelFilter>,
    started: SystemTime,
    /// The same moment on the monotonic clock, for `live`.
    started_at: Instant,
    /// One reload at a time, whichever way it was asked for.
    reloading: tokio::sync::Mutex<()>,
    state: Mutex<State>,
    /// How to start a successor; upgrades are off without it.
    relaunch: std::sync::OnceLock<crate::upgrade::Relaunch>,
}

impl Admin {
    pub fn new(live: Arc<Live>, path: PathBuf, level_override: Option<LevelFilter>) -> Arc<Self> {
        let now = SystemTime::now();
        Arc::new(Self {
            live,
            path,
            level_override,
            started: now,
            started_at: Instant::now(),
            reloading: tokio::sync::Mutex::new(()),
            state: Mutex::new(State {
                loaded: now,
                last_reload: None,
                restart_needed: Vec::new(),
            }),
            relaunch: std::sync::OnceLock::new(),
        })
    }

    /// Enables `upgrade`: a successor is started the way `relaunch` says.
    pub fn set_relaunch(&self, relaunch: crate::upgrade::Relaunch) {
        let _ = self.relaunch.set(relaunch);
    }

    /// Hands the listening sockets to a new process started from `binary`, by default
    /// the binary this one started from.
    pub async fn upgrade(&self, binary: Option<PathBuf>) -> proto::UpgradeReply {
        match self.relaunch.get() {
            Some(r) => self.live.upgrade(r, binary).await,
            None => proto::UpgradeReply {
                schema: proto::UPGRADE_SCHEMA,
                ok: false,
                error: Some("this daemon cannot start a successor".to_owned()),
                config_error: false,
                version: None,
                old_pid: std::process::id(),
                new_pid: None,
                ready_ms: None,
                draining_streams: 0,
                drain_limit_secs: 0,
            },
        }
    }

    pub fn live(&self) -> &Arc<Live> {
        &self.live
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Rereads the configuration file and applies it; on failure the running
    /// configuration stays. Logs the outcome as well as returning it.
    pub async fn reload(&self) -> ReloadReply {
        let _one = self.reloading.lock().await;
        let live = Arc::clone(&self.live);
        let path = self.path.clone();
        // Reading files and resolving new origins block.
        let result = tokio::task::spawn_blocking(move || {
            let config = piano_config::load(&path).map_err(crate::Error::from)?;
            let warnings = config.warnings();
            let level = config.log.level;
            live.apply(&config).map(|fixed| (fixed, warnings, level))
        })
        .await;
        let now = SystemTime::now();
        let reply = match result {
            Ok(Ok((fixed, warnings, level))) => {
                if self.level_override.is_none() {
                    logger::set_level(crate::level_filter(level));
                }
                let warnings: Vec<String> = warnings.iter().map(ToString::to_string).collect();
                for w in &warnings {
                    warn!("{w}");
                }
                if !fixed.is_empty() {
                    warn!("restart needed for: {}", fixed.join(", "));
                }
                info!("configuration reloaded from {}", self.path.display());
                let mut state = self.state();
                state.loaded = now;
                state.restart_needed.clone_from(&fixed);
                ReloadReply {
                    schema: RELOAD_SCHEMA,
                    ok: true,
                    error: None,
                    config_error: false,
                    restart_needed: fixed.iter().map(|s| (*s).to_owned()).collect(),
                    warnings,
                }
            }
            Ok(Err(e)) => {
                warn!("reload failed, keeping the running configuration: {e}");
                failed(e.to_string(), e.is_config())
            }
            Err(e) => {
                error!("reload task failed: {e}");
                failed(format!("reload task failed: {e}"), false)
            }
        };
        self.state().last_reload = Some(ReloadRecord {
            at: unix(now),
            ok: reply.ok,
            error: reply.error.clone(),
        });
        reply
    }

    /// What `piano cache stats` shows.
    pub fn cache(&self) -> CacheStats {
        let s = self.live.images.stats();
        CacheStats {
            schema: CACHE_SCHEMA,
            images: s.images,
            bytes: s.bytes,
            capacity: s.capacity,
            missing: s.missing,
            redirects: s.moved,
            hits: s.hits,
            misses: s.misses,
            coalesced: s.coalesced,
            stale: s.stale,
            revalidated: s.revalidated,
            missing_hits: s.missing_hits,
            shed: s.shed,
            redirect_hits: s.moved_hits,
            upstreams: s
                .budgets
                .into_iter()
                .map(|(upstream, b)| UpstreamBudget {
                    upstream,
                    burst: b.rate.map(|r| r.burst),
                    per_sec: b.rate.map(|r| r.per_sec),
                    tokens: b.tokens,
                    paused_secs: b.paused_for.map(|d| d.as_secs_f64()),
                    limited: b.limited,
                    waiting: b.waiting,
                })
                .collect(),
        }
    }

    /// What `piano top` shows: counters since start and the streams running now.
    pub fn live_view(&self) -> proto::Live {
        let live = &self.live;
        let mut counts = live.metrics.live();
        let sites = live
            .sites
            .load()
            .iter()
            .map(|s| {
                let (total, ttfb) = counts.remove(&s.name).unwrap_or_else(|| {
                    (Counts::default(), [[0; latency::BUCKETS]; Ttfb::ALL.len()])
                });
                SiteLive {
                    name: s.name.clone(),
                    total: wire(&total),
                    ttfb: Ttfb::ALL
                        .iter()
                        .zip(ttfb)
                        .map(|(k, b)| (k.as_str().to_owned(), b.to_vec()))
                        .collect(),
                }
            })
            .collect();
        let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let streams = live
            .streams
            .snapshot()
            .iter()
            .map(|s| StreamLive {
                rid: s.rid.clone(),
                site: s.site.clone(),
                client: s.client.map(|a| a.to_string()),
                path: s.path.clone(),
                range: s.range.clone(),
                age_ms: ms(s.started.elapsed()),
                sent: s.sent(),
                position: s.position(),
                size: s.size(),
                ttfb_ms: s.ttfb().map(ms),
                idle_ms: ms(s.idle()),
                requests: s.requests(),
                hedges: s.hedges(),
                resumes: s.resumes(),
                in_flight: s.sources(),
                client_holds: s.writing(),
                upstream: s.upstream(),
            })
            .collect();
        proto::Live {
            schema: LIVE_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: std::process::id(),
            uptime_ms: ms(self.started_at.elapsed()),
            connections: self.connections(),
            access_log: live.access_log.path().map(|p| p.display().to_string()),
            ttfb_bounds_ms: BOUNDS_US.iter().map(|&b| b as f64 / 1000.0).collect(),
            sites,
            streams,
            cache: self.cache(),
        }
    }

    fn connections(&self) -> Connections {
        let live = &self.live;
        let accept = &live.accept;
        Connections {
            open: accept.open_connections() as u64,
            handshaking: accept.pending_handshakes() as u64,
            limit: (live.fixed.max_connections * live.fixed.listen.len()) as u64,
            closed_at_limit: accept.closed_at_connection_limit(),
            handshake_timeouts: accept.handshake_timeouts(),
            handshake_errors: accept.handshake_errors(),
            denied: live.denied_connections(),
            media_streams: live.streams.len() as u64,
        }
    }

    /// Forgets stored images, remembered redirects and misses.
    pub fn purge(&self) -> PurgeReply {
        let p = self.live.images.purge();
        info!(
            "image cache purged: {} images, {} misses, {} redirects",
            p.images, p.missing, p.moved
        );
        PurgeReply {
            schema: CACHE_SCHEMA,
            images: p.images,
            missing: p.missing,
            redirects: p.moved,
        }
    }

    /// Everything `piano status` shows.
    pub fn status(&self) -> Status {
        let now = SystemTime::now();
        let live = &self.live;
        let report = live.metrics.report();
        let sites = live
            .sites
            .load()
            .iter()
            .map(|s| {
                let counts = report.sites.iter().find(|r| r.name == s.name);
                SiteStatus {
                    ttfb: latencies(counts.map(|c| &c.ttfb_recent)),
                    name: s.name.clone(),
                    host: s.host.clone(),
                    upstream: format!("{}:{}", s.origin.host, s.origin.port),
                    address: s.origin.addrs.current().to_string(),
                    traffic: Traffic {
                        total: counts
                            .map(|c| wire(&c.total))
                            .unwrap_or_else(|| wire(&Counts::default())),
                        recent: counts
                            .map(|c| wire(&c.recent))
                            .unwrap_or_else(|| wire(&Counts::default())),
                    },
                }
            })
            .collect();
        let state = self.state();
        let cert = live.certs.info();
        let mut status = Status {
            schema: STATUS_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: std::process::id(),
            started: unix(self.started),
            uptime_secs: now.duration_since(self.started).map_or(0, |d| d.as_secs()),
            config: ConfigState {
                path: self.path.display().to_string(),
                loaded: unix(state.loaded),
                last_reload: state.last_reload.clone(),
                restart_needed: state
                    .restart_needed
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            },
            process: procfs::process(),
            connections: self.connections(),
            certificate: Certificate {
                names: cert.names,
                not_after: cert.not_after,
                loaded: unix(cert.loaded),
            },
            access_log: proto::AccessLog {
                path: live.access_log.path().map(|p| p.display().to_string()),
                dropped: live.dropped_access_lines(),
            },
            recent_secs: report.span.as_secs(),
            sites,
            unrouted: Traffic {
                total: wire(&report.unrouted.total),
                recent: wire(&report.unrouted.recent),
            },
            ttfb_secs: report.ttfb_span.as_secs(),
            findings: Vec::new(),
        };
        drop(state);
        status.findings = findings(&status, unix(now));
        if let (Some(path), Some(error)) = live.traffic_state() {
            status.findings.push(finding(
                Level::Warn,
                "traffic_unsaved",
                format!("the traffic record cannot be written: {error}"),
                Some(&format!(
                    "the daemon retries every minute; {} must be writable",
                    path.display()
                )),
            ));
            status.findings.sort_by_key(|f| std::cmp::Reverse(f.level));
        }
        status
    }
}

fn failed(error: String, config_error: bool) -> ReloadReply {
    ReloadReply {
        schema: RELOAD_SCHEMA,
        ok: false,
        error: Some(error),
        config_error,
        restart_needed: Vec::new(),
        warnings: Vec::new(),
    }
}

fn wire(c: &Counts) -> proto::Counts {
    proto::Counts {
        requests: c.requests,
        status: STATUS_CLASSES
            .iter()
            .zip(c.status)
            .map(|(k, v)| ((*k).to_owned(), v))
            .collect(),
        ends: End::ALL
            .iter()
            .map(|e| (e.as_str().to_owned(), c.end(*e)))
            .collect(),
        upstream_attempts: c.attempts,
        reused: c.reused,
        bytes_sent: c.sent.iter().sum(),
        bytes_fetched: c.fetched.iter().sum(),
    }
}

/// Percentiles of each histogram, every key present.
fn latencies(ttfb: Option<&TtfbBuckets>) -> std::collections::BTreeMap<String, Latency> {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    Ttfb::ALL
        .iter()
        .map(|k| {
            let b: Option<&Buckets> = ttfb.map(|t| &t[*k as usize]);
            let l = b.map_or_else(Latency::default, |b| Latency {
                count: b.iter().sum(),
                p50_ms: latency::quantile(b, 0.5).map(ms),
                p95_ms: latency::quantile(b, 0.95).map(ms),
            });
            (k.as_str().to_owned(), l)
        })
        .collect()
}

fn near_limit(used: u64, limit: u64) -> bool {
    limit > 0 && used * 100 >= limit * NEAR_LIMIT_PERCENT
}

fn finding(level: Level, code: &str, message: String, hint: Option<&str>) -> Finding {
    Finding {
        level,
        code: code.to_owned(),
        message,
        hint: hint.map(str::to_owned),
    }
}

/// Problems visible in `s` at Unix time `now`, errors first.
fn findings(s: &Status, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(not_after) = s.certificate.not_after {
        let left = not_after - i64::try_from(now).unwrap_or(i64::MAX);
        let days = left.div_euclid(86_400);
        let hint = Some(
            "check the renewal job; renewed files are picked up within an hour, or at once \
             with piano reload",
        );
        if left <= 0 {
            out.push(finding(
                Level::Error,
                "cert_expired",
                "the certificate has expired".into(),
                hint,
            ));
        } else if days < CERT_ERROR_DAYS {
            out.push(finding(
                Level::Error,
                "cert_expiring",
                format!("the certificate expires in {days} days"),
                hint,
            ));
        } else if days < CERT_WARN_DAYS {
            out.push(finding(
                Level::Warn,
                "cert_expiring",
                format!("the certificate expires in {days} days"),
                hint,
            ));
        }
    }
    if let Some(r) = s.config.last_reload.as_ref().filter(|r| !r.ok) {
        out.push(finding(
            Level::Warn,
            "reload_failed",
            format!(
                "the last reload failed; the previous configuration is still in use: {}",
                r.error.as_deref().unwrap_or("unknown error")
            ),
            Some("fix the file, check it with piano config check, then piano reload"),
        ));
    }
    if !s.config.restart_needed.is_empty() {
        out.push(finding(
            Level::Warn,
            "restart_needed",
            format!(
                "changed settings wait for a restart: {}",
                s.config.restart_needed.join(", ")
            ),
            None,
        ));
    }
    let p = &s.process;
    if let (Some(open), Some(max)) = (p.open_files, p.max_open_files)
        && near_limit(open, max)
    {
        out.push(finding(
            Level::Warn,
            "open_files_high",
            format!("{open} of {max} file descriptors in use"),
            Some("raise LimitNOFILE (systemd) or rc_ulimit (OpenRC)"),
        ));
    }
    let c = &s.connections;
    if near_limit(c.open, c.limit) {
        out.push(finding(
            Level::Warn,
            "connections_high",
            format!("{} of {} client connections open", c.open, c.limit),
            Some("limits.max_connections"),
        ));
    }
    if c.closed_at_limit > 0 {
        out.push(finding(
            Level::Warn,
            "connection_limit_hit",
            format!(
                "{} connections closed at the connection limit since start",
                c.closed_at_limit
            ),
            Some("limits.max_connections"),
        ));
    }
    if s.access_log.dropped > 0 {
        out.push(finding(
            Level::Warn,
            "access_log_dropped",
            format!(
                "{} access log lines lost since start; the disk did not keep up",
                s.access_log.dropped
            ),
            None,
        ));
    }
    let hour = if s.recent_secs >= 3600 {
        "in the last hour".to_owned()
    } else {
        format!("in the last {} min", s.recent_secs.div_ceil(60))
    };
    for site in &s.sites {
        let r = &site.traffic.recent;
        let internal = r.end(End::Internal.as_str());
        if internal > 0 {
            out.push(finding(
                Level::Error,
                "internal_error",
                format!(
                    "{}: {internal} requests failed inside piano {hour}",
                    site.name
                ),
                Some("the diagnostic log has the error for each rid"),
            ));
        }
        let refused = r.end(End::RedirectRefused.as_str());
        if refused > 0 {
            out.push(finding(
                Level::Warn,
                "redirect_refused",
                format!("{}: {refused} redirects not followed {hour}", site.name),
                Some("access log lines with end = redirect_refused name the host in err"),
            ));
        }
        let failed: Vec<String> = End::ALL
            .iter()
            .filter(|e| e.is_upstream_failure() && **e != End::RedirectRefused)
            .filter_map(|e| {
                let n = r.end(e.as_str());
                (n > 0).then(|| format!("{} {n}", e.as_str()))
            })
            .collect();
        if !failed.is_empty() {
            out.push(finding(
                Level::Warn,
                "upstream_failures",
                format!(
                    "{}: requests failed upstream {hour}: {}",
                    site.name,
                    failed.join(", ")
                ),
                Some("the access log's up field shows each attempt"),
            ));
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.level));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use piano_ctl::proto::{AccessLog, Process};

    fn status() -> Status {
        Status {
            schema: STATUS_SCHEMA,
            version: "0".into(),
            pid: 1,
            started: 0,
            uptime_secs: 0,
            config: ConfigState {
                path: "/etc/piano/piano.toml".into(),
                loaded: 0,
                last_reload: None,
                restart_needed: Vec::new(),
            },
            process: Process {
                rss_bytes: None,
                threads: None,
                open_files: Some(10),
                max_open_files: Some(1024),
                binary_sha256: None,
            },
            connections: Connections {
                open: 1,
                handshaking: 0,
                limit: 1024,
                closed_at_limit: 0,
                handshake_timeouts: 0,
                handshake_errors: 0,
                denied: 0,
                media_streams: 0,
            },
            certificate: Certificate {
                names: Vec::new(),
                not_after: Some(100 * 86_400),
                loaded: 0,
            },
            access_log: AccessLog {
                path: None,
                dropped: 0,
            },
            recent_secs: 600,
            sites: vec![SiteStatus {
                name: "a".into(),
                host: "a.example.com".into(),
                upstream: "emby.example.net:443".into(),
                address: "192.0.2.1:443".into(),
                ttfb: latencies(None),
                traffic: Traffic {
                    total: wire(&Counts::default()),
                    recent: wire(&Counts::default()),
                },
            }],
            unrouted: Traffic::default(),
            ttfb_secs: 0,
            findings: Vec::new(),
        }
    }

    fn codes(s: &Status, now: u64) -> Vec<String> {
        findings(s, now).into_iter().map(|f| f.code).collect()
    }

    #[test]
    fn a_healthy_status_has_no_findings() {
        assert!(codes(&status(), 0).is_empty());
    }

    #[test]
    fn certificate_expiry_thresholds() {
        let s = status();
        let day = 86_400;
        assert!(codes(&s, 86 * day).is_empty());
        assert_eq!(findings(&s, 87 * day)[0].level, Level::Warn);
        assert_eq!(findings(&s, 98 * day)[0].level, Level::Error);
        assert_eq!(codes(&s, 100 * day), ["cert_expired"]);
    }

    #[test]
    fn upstream_failures_and_errors_come_first() {
        let mut s = status();
        let mut recent = Counts::default();
        recent.ends[End::ConnectFailed as usize] = 2;
        recent.ends[End::Internal as usize] = 1;
        s.sites[0].traffic.recent = wire(&recent);
        s.access_log.dropped = 3;
        let f = findings(&s, 0);
        let codes: Vec<&str> = f.iter().map(|f| f.code.as_str()).collect();
        assert_eq!(
            codes,
            ["internal_error", "access_log_dropped", "upstream_failures"]
        );
        assert!(
            f[2].message.contains("connect_failed 2"),
            "{}",
            f[2].message
        );
        assert!(f[2].message.contains("last 10 min"), "{}", f[2].message);
    }

    #[test]
    fn near_limits() {
        let mut s = status();
        s.process.open_files = Some(900);
        s.connections.open = 820;
        s.connections.closed_at_limit = 1;
        assert_eq!(
            codes(&s, 0),
            [
                "open_files_high",
                "connections_high",
                "connection_limit_hit"
            ]
        );
    }
}
