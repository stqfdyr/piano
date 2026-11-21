//! `piano doctor`: what `piano status` cannot see. Whether the daemon could start (the
//! configuration, the certificate, files the service user must read and write, the
//! listening ports), whether what is on disk still matches what runs (configuration,
//! certificate files, the binary), and whether every upstream host answers a TLS
//! handshake now, also for sites nobody is using.

use crate::admin::{CERT_ERROR_DAYS, CERT_WARN_DAYS};
use piano_config::Config;
use piano_ctl::proto::{Level as FindingLevel, Status};
use piano_upstream::Resolver;
use piano_upstream::tls::client_config;
use pingora_core::connectors::{ConnectorOptions, TransportConnector};
use pingora_core::protocols::ALPN;
use pingora_core::upstreams::peer::HttpPeer;
use serde::Serialize;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DOCTOR_SCHEMA: u32 = 1;

/// Longest wait for one upstream host: resolving, connecting and the TLS handshake.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// Directories the service managers create when the service starts.
const CREATED_AT_START: [&str; 3] = ["/run/piano", "/var/lib/piano", "/var/log/piano"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    /// Not checked, with the reason.
    Skip,
    Warn,
    Error,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub group: &'static str,
    pub level: Level,
    pub what: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether the configuration did not load, which leaves no other check.
    pub fn config_failed(&self) -> bool {
        self.checks
            .first()
            .is_some_and(|c| c.group == "configuration" && c.level == Level::Error)
    }

    /// The worst level found.
    pub fn worst(&self) -> Level {
        self.checks
            .iter()
            .map(|c| c.level)
            .max()
            .unwrap_or(Level::Ok)
    }
}

/// What the checks look at.
pub struct Input<'a> {
    pub config: &'a Path,
    /// The running daemon's status, when it answered.
    pub status: Option<&'a Status>,
    /// The control socket asked for the status; `None` when it is off.
    pub socket: Option<&'a Path>,
    /// The service user when no daemon runs.
    pub user: &'a str,
    /// The binary on disk to compare with the running one.
    pub installed: Option<Installed>,
    pub resolver: Resolver,
}

/// A binary on disk.
pub struct Installed {
    pub path: PathBuf,
    pub sha256: String,
    /// `path` is where the daemon was started from, which `piano upgrade` runs again.
    pub started_from: bool,
}

/// Runs every check; a configuration that does not load leaves only that check.
pub async fn run(input: &Input<'_>) -> Report {
    let mut out = Checks::default();
    let config = match piano_config::load(input.config) {
        Ok(c) => {
            out.push(
                "configuration",
                Level::Ok,
                input.config.display().to_string(),
                format!("{} sites", c.sites.len()),
            );
            for w in c.warnings() {
                out.push(
                    "configuration",
                    Level::Warn,
                    "warning".into(),
                    w.to_string(),
                );
            }
            c
        }
        Err(e) => {
            out.push(
                "configuration",
                Level::Error,
                input.config.display().to_string(),
                e.to_string(),
            );
            return out.report();
        }
    };
    certificate(&mut out, &config);
    access(&mut out, &config, input);
    daemon(&mut out, &config, input);
    listening(&mut out, &config, input.status);
    upstreams(&mut out, &config, &input.resolver).await;
    out.report()
}

#[derive(Default)]
struct Checks(Vec<Check>);

impl Checks {
    fn push(&mut self, group: &'static str, level: Level, what: String, detail: String) {
        self.0.push(Check {
            group,
            level,
            what,
            detail,
        });
    }

    fn report(self) -> Report {
        Report {
            schema: DOCTOR_SCHEMA,
            checks: self.0,
        }
    }
}

fn certificate(out: &mut Checks, config: &Config) {
    match piano_edge::tls::SniTable::load(config) {
        Ok(table) => {
            let info = table.info();
            let (level, detail) = expiry(info.not_after, unix_now());
            out.push(
                "configuration",
                level,
                config.tls.cert.display().to_string(),
                detail,
            );
            if info.incomplete_chain {
                out.push(
                    "configuration",
                    Level::Warn,
                    config.tls.cert.display().to_string(),
                    piano_edge::tls::INCOMPLETE_CHAIN.into(),
                );
            }
        }
        Err(e) => out.push(
            "configuration",
            Level::Error,
            config.tls.cert.display().to_string(),
            e.to_string(),
        ),
    }
    if let Err(e) = client_config(&config.upstream.extra_roots) {
        out.push(
            "configuration",
            Level::Error,
            "upstream.extra_roots".into(),
            e.to_string(),
        );
    }
}

/// How soon a certificate expiring at `not_after` does, at `now` (both Unix seconds).
fn expiry(not_after: Option<i64>, now: i64) -> (Level, String) {
    match not_after {
        None => (Level::Warn, "expiry unreadable".to_owned()),
        Some(t) if t <= now => (Level::Error, "expired".to_owned()),
        Some(t) => {
            let days = (t - now).div_euclid(86_400);
            let level = if days < CERT_ERROR_DAYS {
                Level::Error
            } else if days < CERT_WARN_DAYS {
                Level::Warn
            } else {
                Level::Ok
            };
            (level, format!("covers every site, expires in {days} days"))
        }
    }
}

/// A user's identity as the kernel checks file access.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Who {
    name: String,
    uid: u32,
    gids: Vec<u32>,
}

/// The daemon's identity from `/proc`, else the named user's.
fn service_user(status: Option<&Status>, user: &str) -> Result<Who, String> {
    if let Some(s) = status
        && let Ok(text) = std::fs::read_to_string(format!("/proc/{}/status", s.pid))
        && let Some(mut who) = proc_identity(&text, &format!("pid {}", s.pid))
    {
        if let Ok(Some(u)) = nix::unistd::User::from_uid(who.uid.into()) {
            who.name = format!("{} (pid {})", u.name, s.pid);
        }
        return Ok(who);
    }
    let found = nix::unistd::User::from_name(user)
        .map_err(|e| format!("cannot look up user {user}: {e}"))?
        .ok_or_else(|| format!("no user {user}; give the service user with --user"))?;
    let name = std::ffi::CString::new(user).map_err(|e| e.to_string())?;
    let gids = nix::unistd::getgrouplist(&name, found.gid)
        .map_err(|e| format!("groups of {user}: {e}"))?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    Ok(Who {
        name: user.to_owned(),
        uid: found.uid.as_raw(),
        gids,
    })
}

/// Effective uid and the groups of a `/proc/<pid>/status` text.
fn proc_identity(status: &str, name: &str) -> Option<Who> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            .map(|v| {
                v.split_whitespace()
                    .filter_map(|n| n.parse::<u32>().ok())
                    .collect::<Vec<_>>()
            })
    };
    let uid = *field("Uid")?.get(1)?;
    let mut gids = vec![*field("Gid")?.get(1)?];
    gids.extend(field("Groups").unwrap_or_default());
    Some(Who {
        name: name.to_owned(),
        uid,
        gids,
    })
}

#[derive(Debug, Clone, Copy)]
enum Want {
    Read,
    Write,
    Enter,
}

/// Whether `who` may `want` a file of `mode` owned by `owner`:`group`, by the
/// permission bits alone (root may do anything).
fn permits(who: &Who, mode: u32, owner: u32, group: u32, want: Want) -> bool {
    if who.uid == 0 {
        return true;
    }
    let bit = match want {
        Want::Read => 4,
        Want::Write => 2,
        Want::Enter => 1,
    };
    let shift = if owner == who.uid {
        6
    } else if who.gids.contains(&group) {
        3
    } else {
        0
    };
    mode >> shift & bit != 0
}

/// Checks that `who` can enter every directory on the way to `path` and, through
/// symbolic links, to the file itself, then `want` it.
fn reach(who: &Who, path: &Path, want: Want) -> Result<(), String> {
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for target in [path, real.as_path()] {
        // A relative path's last ancestor is empty; the real path covers the directories
        // above it.
        for dir in target
            .ancestors()
            .skip(1)
            .filter(|d| !d.as_os_str().is_empty())
        {
            let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if !permits(who, m.mode(), m.uid(), m.gid(), Want::Enter) {
                return Err(format!("cannot enter {}", dir.display()));
            }
        }
    }
    let m = std::fs::metadata(&real).map_err(|e| format!("{}: {e}", real.display()))?;
    if permits(who, m.mode(), m.uid(), m.gid(), want) {
        Ok(())
    } else {
        Err(format!(
            "cannot {} {}",
            match want {
                Want::Read => "read",
                Want::Write => "write",
                Want::Enter => "enter",
            },
            real.display()
        ))
    }
}

fn access(out: &mut Checks, config: &Config, input: &Input<'_>) {
    let who = match service_user(input.status, input.user) {
        Ok(w) => w,
        Err(e) => {
            out.push("access", Level::Skip, "service user".into(), e);
            return;
        }
    };
    let group = "access";
    let systemd = Path::new("/run/systemd/system").exists();
    let label = |p: &Path| format!("{} reads {}", who.name, p.display());
    for path in [input.config, &config.tls.cert, &config.tls.key] {
        match reach(&who, path, Want::Read) {
            Ok(()) => out.push(group, Level::Ok, label(path), String::new()),
            Err(e) => out.push(group, Level::Error, label(path), e),
        }
    }
    let written = [
        ("access log", config.log.access_path()),
        ("traffic record", config.traffic.file_path()),
        ("control socket", config.control.socket_path()),
    ];
    for (name, path) in written {
        let Some(path) = path else { continue };
        let Some(dir) = path.parent() else { continue };
        let what = format!("{} writes {} ({name})", who.name, dir.display());
        if !dir.exists() {
            let made = CREATED_AT_START.iter().any(|d| dir == Path::new(d));
            let (level, detail) = if made {
                (Level::Ok, "created when the service starts".to_owned())
            } else {
                (Level::Error, "does not exist".to_owned())
            };
            out.push(group, level, what, detail);
            continue;
        }
        let result = reach(&who, dir, Want::Write).and_then(|()| reach(&who, dir, Want::Enter));
        let result = result.and_then(|()| {
            // The access log is appended to; the others are replaced or created.
            if name == "access log" && path.exists() {
                reach(&who, path, Want::Write)
            } else {
                Ok(())
            }
        });
        match result {
            Ok(()) if systemd && outside_service_dirs(dir) => out.push(
                group,
                Level::Ok,
                what,
                "under systemd the service unit must also list it in ReadWritePaths=".into(),
            ),
            Ok(()) => out.push(group, Level::Ok, what, String::new()),
            Err(e) => out.push(group, Level::Error, what, e),
        }
    }
}

/// Whether `dir` is outside the directories the service unit makes writable, where its
/// `ProtectSystem=strict` leaves everything read-only.
fn outside_service_dirs(dir: &Path) -> bool {
    !CREATED_AT_START.iter().any(|d| dir.starts_with(d))
}

fn daemon(out: &mut Checks, config: &Config, input: &Input<'_>) {
    let group = "daemon";
    let Some(s) = input.status else {
        let detail = match input.socket {
            Some(p) => format!("nothing answers on {}", p.display()),
            None => "the control socket is off".to_owned(),
        };
        out.push(group, Level::Warn, "not running".into(), detail);
        return;
    };
    out.push(
        group,
        Level::Ok,
        format!("pid {}", s.pid),
        format!("{}, up {}", s.version, uptime(s.uptime_secs)),
    );
    let newer = |path: &Path, than: u64| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .is_some_and(|t| t.as_secs() > than)
    };
    if newer(input.config, s.config.loaded) {
        out.push(
            group,
            Level::Warn,
            input.config.display().to_string(),
            "changed after the daemon loaded it; piano reload applies it".into(),
        );
    }
    for path in [&config.tls.cert, &config.tls.key] {
        if newer(path, s.certificate.loaded) {
            out.push(
                group,
                Level::Warn,
                path.display().to_string(),
                "changed after the daemon loaded it; it is picked up within the hour, or \
                 at once with piano reload"
                    .into(),
            );
        }
    }
    match (&input.installed, &s.process.binary_sha256) {
        (Some(installed), Some(running)) if &installed.sha256 != running => {
            let path = installed.path.display();
            let upgrade = if installed.started_from {
                "piano upgrade".to_owned()
            } else {
                format!("piano upgrade {path}")
            };
            out.push(
                group,
                Level::Warn,
                "binary".into(),
                format!(
                    "{path} is not the binary running; {upgrade} switches to it without \
                     dropping streams"
                ),
            );
        }
        (Some(_), None) => out.push(
            group,
            Level::Skip,
            "binary".into(),
            "the running binary is too old to report its checksum".into(),
        ),
        _ => {}
    }
    for f in &s.findings {
        let level = match f.level {
            FindingLevel::Warn => Level::Warn,
            FindingLevel::Error => Level::Error,
        };
        out.push(group, level, f.code.clone(), f.message.clone());
    }
}

/// A listening TCP socket from `/proc/net/tcp*`: its port and inode.
fn listeners(table: &str) -> Vec<(u16, u64)> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let port = u16::from_str_radix(f.get(1)?.rsplit(':').next()?, 16).ok()?;
            (*f.get(3)? == "0A").then_some(())?;
            Some((port, f.get(9)?.parse().ok()?))
        })
        .collect()
}

/// The process holding socket `inode`: pid and command name.
fn socket_owner(inode: u64) -> Option<(u32, String)> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == target.as_str()) {
                let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
                return Some((pid, comm.trim().to_owned()));
            }
        }
    }
    None
}

fn listening(out: &mut Checks, config: &Config, status: Option<&Status>) {
    let tables: String = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect::<Vec<_>>()
        .join("\n");
    let held = listeners(&tables);
    for listen in &config.server.listen {
        let Ok(addr) = listen.parse::<SocketAddr>() else {
            continue;
        };
        let owners: BTreeSet<(u32, String)> = held
            .iter()
            .filter(|(port, _)| *port == addr.port())
            .filter_map(|(_, inode)| socket_owner(*inode))
            .collect();
        let in_use = held.iter().any(|(p, _)| *p == addr.port());
        let (level, detail) = port_verdict(addr.port(), status.map(|s| s.pid), &owners, in_use);
        out.push("listening", level, listen.clone(), detail);
    }
}

/// The verdict on listening `port`, given the running daemon's pid, the processes this
/// user can see holding it, and whether anyone listens on it. A draining predecessor of
/// the daemon (also `piano`) does not conflict.
fn port_verdict(
    port: u16,
    daemon: Option<u32>,
    owners: &BTreeSet<(u32, String)>,
    in_use: bool,
) -> (Level, String) {
    let others: Vec<String> = owners
        .iter()
        .filter(|(pid, comm)| Some(*pid) != daemon && !(daemon.is_some() && comm == "piano"))
        .map(|(pid, comm)| format!("{comm} (pid {pid})"))
        .collect();
    match (daemon, others.is_empty()) {
        (_, false) => (
            Level::Error,
            format!("port {port} is held by {}", others.join(", ")),
        ),
        (Some(pid), true) => (Level::Ok, format!("served by pid {pid}")),
        (None, true) if !in_use => (Level::Ok, "free".to_owned()),
        (None, true) => (
            Level::Warn,
            format!("port {port} is in use by a process this user cannot see"),
        ),
    }
}

/// Hosts a site's requests go to: (site, host, port, whether only public addresses
/// are accepted).
fn upstream_hosts(config: &Config) -> Vec<(String, String, u16, bool)> {
    let mut seen = BTreeSet::new();
    let mut hosts = Vec::new();
    for site in &config.sites {
        let Some(url) = &site.upstream_url else {
            continue;
        };
        let own = std::iter::once(url.host.clone())
            .chain(site.aliases.iter().cloned())
            .chain(site.mounts.values().cloned())
            .map(|h| (h, url.port, false));
        let followed = site
            .follow
            .iter()
            .filter(|h| !h.starts_with("*."))
            .map(|h| (h.clone(), 443, true));
        for (host, port, public) in own.chain(followed) {
            let host = host.to_ascii_lowercase();
            if seen.insert((host.clone(), port)) {
                hosts.push((site.name.clone(), host, port, public));
            }
        }
    }
    hosts
}

async fn upstreams(out: &mut Checks, config: &Config, resolver: &Resolver) {
    let tls = match client_config(&config.upstream.extra_roots) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut options = ConnectorOptions::new(0);
    options.rustls_client_config = Some((tls.config, tls.roots));
    let connector = std::sync::Arc::new(TransportConnector::new(Some(options)));
    let connect_timeout = config.upstream.connect_timeout.get();
    let mut tasks = tokio::task::JoinSet::new();
    for (i, (site, host, port, public)) in upstream_hosts(config).into_iter().enumerate() {
        let connector = std::sync::Arc::clone(&connector);
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let checked = tokio::time::timeout(
                UPSTREAM_TIMEOUT,
                handshake(&connector, &resolver, &host, port, public, connect_timeout),
            )
            .await
            .unwrap_or_else(|_| Err(format!("no answer within {}s", UPSTREAM_TIMEOUT.as_secs())));
            (i, site, host, port, checked)
        });
    }
    let mut done = Vec::new();
    while let Some(Ok(r)) = tasks.join_next().await {
        done.push(r);
    }
    done.sort_by_key(|r| r.0);
    for (_, site, host, port, checked) in done {
        let what = format!("{site}: {host}:{port}");
        match checked {
            Ok(detail) => out.push("upstreams", Level::Ok, what, detail),
            Err(e) => out.push("upstreams", Level::Error, what, e),
        }
    }
    // The hosts these stand for are known only when a redirect names one.
    for site in &config.sites {
        for name in site.follow.iter().filter(|h| h.starts_with("*.")) {
            out.push(
                "upstreams",
                Level::Skip,
                format!("{}: {name}", site.name),
                "checked when a redirect names a host".into(),
            );
        }
    }
}

/// Resolves `host` and completes a verified TLS handshake with its first address.
async fn handshake(
    connector: &TransportConnector,
    resolver: &Resolver,
    host: &str,
    port: u16,
    public: bool,
    connect_timeout: Duration,
) -> Result<String, String> {
    let addrs = if public {
        resolver.resolve_public(host, port).await
    } else {
        let (r, h) = (resolver.clone(), host.to_owned());
        tokio::task::spawn_blocking(move || r.resolve_blocking(&h, port))
            .await
            .map_err(|e| e.to_string())?
    }
    .map_err(|e| e.to_string())?;
    let addr = addrs
        .current()
        .ok_or_else(|| format!("{host} has no address"))?;
    let mut peer = HttpPeer::new(addr, true, host.to_owned()).map_err(|e| e.to_string())?;
    let o = &mut peer.options;
    o.alpn = ALPN::H1;
    o.verify_cert = true;
    o.verify_hostname = true;
    o.connection_timeout = Some(connect_timeout);
    o.total_connection_timeout = Some(connect_timeout);
    let start = Instant::now();
    let stream = connector
        .new_stream(&peer)
        .await
        .map_err(|e| crate::probe::describe(&e))?;
    drop(stream);
    Ok(format!(
        "{} in {} ms",
        addr.ip(),
        start.elapsed().as_millis()
    ))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `3d 4h`, `2h 5m`, `5m`, `40s`.
fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    match () {
        () if d > 0 => format!("{d}d {h}h"),
        () if h > 0 => format!("{h}h {m}m"),
        () if m > 0 => format!("{m}m"),
        () => format!("{secs}s"),
    }
}

/// The file process `pid` was started from, at its path now; `None` when its link
/// cannot be read (another user's process).
pub fn started_from(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|link| undeleted(&link))
}

/// An `exe` link's path without the " (deleted)" the kernel appends once the file
/// there was replaced.
fn undeleted(link: &Path) -> PathBuf {
    let b = link.as_os_str().as_bytes();
    PathBuf::from(OsStr::from_bytes(
        b.strip_suffix(b" (deleted)").unwrap_or(b),
    ))
}

/// sha256 of a file, in hex.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    crate::procfs::sha256_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(uid: u32, gids: &[u32]) -> Who {
        Who {
            name: "piano".into(),
            uid,
            gids: gids.to_vec(),
        }
    }

    #[test]
    fn permission_bits_by_owner_group_other() {
        let w = who(100, &[100, 50]);
        // owner
        assert!(permits(&w, 0o600, 100, 0, Want::Read));
        assert!(!permits(&w, 0o060, 100, 50, Want::Read));
        // group, when not the owner
        assert!(permits(&w, 0o640, 0, 50, Want::Read));
        assert!(!permits(&w, 0o600, 0, 50, Want::Read));
        assert!(permits(&w, 0o750, 0, 100, Want::Enter));
        assert!(!permits(&w, 0o750, 0, 7, Want::Enter));
        // other
        assert!(permits(&w, 0o644, 0, 0, Want::Read));
        assert!(!permits(&w, 0o644, 0, 0, Want::Write));
        assert!(permits(&who(0, &[0]), 0o000, 1, 1, Want::Write));
    }

    #[test]
    fn identity_from_proc_status() {
        let s = "Name:\tpiano\nUid:\t0\t101\t101\t101\nGid:\t0\t102\t102\t102\nGroups:\t102 7 \n";
        assert_eq!(
            proc_identity(s, "pid 1"),
            Some(who(101, &[102, 102, 7])).map(|mut w| {
                w.name = "pid 1".into();
                w
            })
        );
        assert_eq!(proc_identity("Name:\tx\n", "pid 1"), None);
    }

    #[test]
    fn listening_sockets_from_proc_net() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 \x20  0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0\n\
                 \x20  1: 0100007F:20FB 0100007F:01BB 01 00000000:00000000 00:00000000 00000000     0        0 999 1 0 100 0 0 10 0\n";
        assert_eq!(listeners(t), vec![(443, 12345)]);
    }

    #[test]
    fn reach_follows_links_and_directories() {
        let me =
            proc_identity(&std::fs::read_to_string("/proc/self/status").unwrap(), "me").unwrap();
        let exe = std::env::current_exe().unwrap();
        assert!(reach(&me, &exe, Want::Read).is_ok());
        assert!(reach(&me, Path::new("/nonexistent/x"), Want::Read).is_err());
        // Relative to the package directory, where tests run.
        assert_eq!(reach(&me, Path::new("Cargo.toml"), Want::Read), Ok(()));
        assert_eq!(reach(&me, Path::new("src/doctor.rs"), Want::Read), Ok(()));
    }

    #[test]
    fn certificate_expiry_levels() {
        let day = 86_400;
        let now = 1_000 * day;
        let at = |days: i64| expiry(Some(now + days * day), now).0;
        assert_eq!(expiry(None, now).0, Level::Warn);
        assert_eq!(expiry(Some(now), now).0, Level::Error);
        assert_eq!(at(CERT_ERROR_DAYS), Level::Warn);
        assert_eq!(
            expiry(Some(now + CERT_ERROR_DAYS * day - 1), now).0,
            Level::Error
        );
        assert_eq!(at(CERT_WARN_DAYS), Level::Ok);
        assert_eq!(
            expiry(Some(now + CERT_WARN_DAYS * day - 1), now).0,
            Level::Warn
        );
        assert_eq!(
            expiry(Some(now + 30 * day + 5), now).1,
            "covers every site, expires in 30 days"
        );
    }

    #[test]
    fn who_holds_a_port() {
        let owners = |list: &[(u32, &str)]| -> BTreeSet<(u32, String)> {
            list.iter().map(|(p, c)| (*p, (*c).to_owned())).collect()
        };
        let v =
            |daemon, list: &[(u32, &str)], in_use| port_verdict(443, daemon, &owners(list), in_use);
        assert_eq!(v(None, &[], false), (Level::Ok, "free".into()));
        assert_eq!(v(None, &[], true).0, Level::Warn);
        assert_eq!(
            v(None, &[(7, "nginx")], true),
            (Level::Error, "port 443 is held by nginx (pid 7)".into())
        );
        assert_eq!(
            v(Some(9), &[(9, "piano")], true),
            (Level::Ok, "served by pid 9".into())
        );
        // A draining predecessor shares the port with the daemon; with no daemon running
        // a piano holding it is a conflict.
        assert_eq!(v(Some(9), &[(8, "piano"), (9, "piano")], true).0, Level::Ok);
        assert_eq!(v(None, &[(8, "piano")], true).0, Level::Error);
        assert_eq!(
            v(Some(9), &[(7, "nginx"), (9, "piano")], true).0,
            Level::Error
        );
        // The daemon's socket can be invisible to this user.
        assert_eq!(v(Some(9), &[], true).0, Level::Ok);
    }

    #[test]
    fn uptimes() {
        assert_eq!(uptime(40), "40s");
        assert_eq!(uptime(5 * 60 + 7), "5m");
        assert_eq!(uptime(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(uptime(3 * 86_400 + 4 * 3600 + 59), "3d 4h");
    }

    #[test]
    fn replaced_binaries_are_read_at_their_path() {
        assert_eq!(
            undeleted(Path::new("/usr/local/bin/piano (deleted)")),
            Path::new("/usr/local/bin/piano")
        );
        assert_eq!(undeleted(Path::new("/opt/piano")), Path::new("/opt/piano"));
        assert_eq!(
            started_from(std::process::id()),
            Some(std::env::current_exe().unwrap())
        );
        assert!(!outside_service_dirs(Path::new("/var/log/piano")));
        assert!(!outside_service_dirs(Path::new("/var/lib/piano/sub")));
        assert!(outside_service_dirs(Path::new("/srv/logs")));
    }
}
