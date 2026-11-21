//! `piano upgrade`: a new process takes over the listening sockets while this one keeps
//! serving its media streams until they end.
//!
//! The old process checks the new binary against the configuration, starts it with
//! `run --takeover <old pid>` and lets pingora offer it the listening sockets. The new
//! process reports on a socket next to the control socket once it accepts on them; only
//! then does the old one stop accepting and drain. Without that report within
//! [`READY_WAIT`] the new process is killed and the old one goes on as before.

use crate::{Live, RUNTIME_GROUP};
use log::{info, warn};
use piano_ctl::proto::{UPGRADE_SCHEMA, UpgradeReply};
use pingora_core::server::{ListenFds, ShutdownWatch};
use pingora_core::services::{ServiceReadyNotifier, ServiceWithDependents};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::{Notify, oneshot};

/// Attempts, one second apart, to hand the listening sockets to the new process once it
/// listens for them; the new process waits one attempt longer for them. pingora's main loop
/// handles no signal while it tries, so a new process that dies just then must not hold
/// it up for long.
pub const HANDOFF_ATTEMPTS: usize = 5;
/// How long the new process has to load its configuration, resolve the upstreams and
/// listen for the sockets.
const LISTEN_WAIT: Duration = Duration::from_secs(30);
/// How often to look for the new process's socket.
const LISTEN_POLL: Duration = Duration::from_millis(50);
/// How long the old process waits for the sockets to be handed over, attempts included.
const HANDOFF_WAIT: Duration = Duration::from_secs(HANDOFF_ATTEMPTS as u64 + 15);
/// How long the new process has, once it holds the sockets, to accept on them.
const READY_WAIT: Duration = Duration::from_secs(30);
/// Limit on running the new binary for its version and configuration check.
const CHECK_WAIT: Duration = Duration::from_secs(15);
/// What `config check` exits with when the configuration is valid but has warnings.
const CHECK_WARNINGS: i32 = 3;
/// What `config check` exits with when the configuration is invalid.
const CHECK_INVALID: i32 = 2;

/// How this process was started, to start its successor the same way.
#[derive(Debug, Clone)]
pub struct Relaunch {
    /// The binary as `/proc/self/exe` named it at startup (symlinks resolved), so a file
    /// installed over it is what runs next, a symlink pointed elsewhere is not.
    pub exe: PathBuf,
    pub config: PathBuf,
    pub log_level: Option<String>,
    pub pidfile: Option<PathBuf>,
}

/// pingora's report that it offered the sockets, and where the decision goes back.
type Report = (bool, oneshot::Sender<bool>);

/// Connects the `upgrade` command with pingora's handoff hook.
#[derive(Default)]
pub struct Upgrader {
    requested: Notify,
    report: Mutex<Option<oneshot::Sender<Report>>>,
    busy: tokio::sync::Mutex<()>,
}

impl Upgrader {
    /// Resolves once an upgrade asks the server to offer its sockets.
    pub(crate) async fn requested(&self) {
        self.requested.notified().await;
    }

    fn report_slot(&self) -> std::sync::MutexGuard<'_, Option<oneshot::Sender<Report>>> {
        self.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// pingora's handoff hook: `sent` tells whether the sockets reached the new process;
    /// resolves to whether to stop accepting.
    pub(crate) async fn handoff(&self, sent: bool) -> bool {
        let Some(tx) = self.report_slot().take() else {
            return false;
        };
        let (decide, decision) = oneshot::channel();
        if tx.send((sent, decide)).is_err() {
            return false;
        }
        decision.await.unwrap_or(false)
    }
}

/// Runs an upgrade to `binary`, by default the binary this process started from.
pub(crate) async fn upgrade(
    live: &Arc<Live>,
    relaunch: &Relaunch,
    binary: Option<PathBuf>,
) -> UpgradeReply {
    let mut reply = UpgradeReply {
        schema: UPGRADE_SCHEMA,
        ok: false,
        error: None,
        config_error: false,
        version: None,
        old_pid: std::process::id(),
        new_pid: None,
        ready_ms: None,
        draining_streams: 0,
        drain_limit_secs: live.fixed.drain_timeout.get().as_secs(),
    };
    match try_upgrade(live, relaunch, binary, &mut reply).await {
        Ok(()) => {
            reply.ok = true;
            info!(
                "upgrade: pid {} serves after {} ms; draining {} media streams for up to {}s",
                reply.new_pid.unwrap_or_default(),
                reply.ready_ms.unwrap_or_default(),
                reply.draining_streams,
                reply.drain_limit_secs
            );
        }
        Err(e) => {
            warn!("upgrade abandoned, still serving: {e}");
            reply.error = Some(e);
        }
    }
    reply
}

async fn try_upgrade(
    live: &Arc<Live>,
    relaunch: &Relaunch,
    binary: Option<PathBuf>,
    reply: &mut UpgradeReply,
) -> Result<(), String> {
    let Ok(_one) = live.upgrader.busy.try_lock() else {
        return Err("an upgrade is already in progress".to_owned());
    };
    let ready_path = live
        .ready_socket()
        .ok_or("upgrading needs the control socket (control.socket)")?;
    let exe = binary.unwrap_or_else(|| relaunch.exe.clone());
    reply.version = Some(check(&exe, relaunch, reply).await?);

    let _ = std::fs::remove_file(&ready_path);
    let ready =
        UnixListener::bind(&ready_path).map_err(|e| format!("{}: {e}", ready_path.display()))?;
    let result = hand_over(live, relaunch, &exe, &ready, reply).await;
    let _ = std::fs::remove_file(&ready_path);
    result
}

/// Runs the new binary for its version and a check of the configuration file.
async fn check(
    exe: &Path,
    relaunch: &Relaunch,
    reply: &mut UpgradeReply,
) -> Result<String, String> {
    let shown = exe.display();
    let version = run_check(Command::new(exe).arg("--version"))
        .await
        .map_err(|e| format!("cannot run {shown}: {e}"))?;
    if !version.status.success() {
        return Err(format!("{shown} --version failed ({})", version.status));
    }
    let version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
    let checked = run_check(
        Command::new(exe)
            .arg("-c")
            .arg(&relaunch.config)
            .args(["config", "check"]),
    )
    .await
    .map_err(|e| format!("cannot run {shown}: {e}"))?;
    match checked.status.code() {
        Some(0 | CHECK_WARNINGS) => Ok(version),
        code => {
            reply.config_error = code == Some(CHECK_INVALID);
            let mut text = String::from_utf8_lossy(&checked.stderr).into_owned();
            text.push_str(&String::from_utf8_lossy(&checked.stdout));
            Err(format!(
                "{version} rejects {}:\n{}",
                relaunch.config.display(),
                text.trim()
            ))
        }
    }
}

async fn run_check(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    cmd.stdin(Stdio::null()).kill_on_drop(true);
    tokio::time::timeout(CHECK_WAIT, cmd.output())
        .await
        .map_err(|_| std::io::Error::other(format!("no answer within {CHECK_WAIT:?}")))?
}

/// Starts the new process and lets it take over; on any failure it is killed.
async fn hand_over(
    live: &Arc<Live>,
    relaunch: &Relaunch,
    exe: &Path,
    ready: &UnixListener,
    reply: &mut UpgradeReply,
) -> Result<(), String> {
    let started = Instant::now();
    let listen_path = live
        .upgrade_socket()
        .ok_or("upgrading needs the control socket (control.socket)")?;
    // Left over from an upgrade that failed, it would look like the new process listening.
    let _ = std::fs::remove_file(&listen_path);
    let mut cmd = Command::new(exe);
    cmd.arg("-c").arg(&relaunch.config);
    if let Some(level) = &relaunch.log_level {
        cmd.args(["--log-level", level]);
    }
    cmd.args(["run", "--takeover", &std::process::id().to_string()]);
    if let Some(p) = &relaunch.pidfile {
        cmd.arg("--pidfile").arg(p);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", exe.display()))?;
    let pid = child.id().ok_or("the new process is already gone")?;
    reply.new_pid = Some(pid);
    info!("upgrade: started {} as pid {pid}", exe.display());

    // Offered only once the new process listens: pingora then sends them at once.
    let listening = tokio::select! {
        r = tokio::time::timeout(LISTEN_WAIT, appears(&listen_path)) => r.is_ok(),
        status = child.wait() => return Err(exited(status)),
    };
    if !listening {
        stop(&mut child).await;
        return Err(format!(
            "the new process did not get ready for the listening sockets within {LISTEN_WAIT:?}"
        ));
    }

    let (tx, rx) = oneshot::channel();
    *live.upgrader.report_slot() = Some(tx);
    live.upgrader.requested.notify_one();
    let report = tokio::select! {
        r = tokio::time::timeout(HANDOFF_WAIT, rx) => r.ok().and_then(Result::ok),
        status = child.wait() => {
            live.upgrader.report_slot().take();
            return Err(exited(status));
        }
    };
    let Some((sent, decide)) = report else {
        live.upgrader.report_slot().take();
        stop(&mut child).await;
        return Err(format!(
            "the listening sockets were not handed over within {HANDOFF_WAIT:?}"
        ));
    };
    if !sent {
        let _ = decide.send(false);
        stop(&mut child).await;
        return Err("the new process did not take the listening sockets".to_owned());
    }
    let serving = tokio::select! {
        r = tokio::time::timeout(READY_WAIT, reported(ready, pid)) => r.is_ok(),
        status = child.wait() => {
            let _ = decide.send(false);
            return Err(exited(status));
        }
    };
    if !serving {
        let _ = decide.send(false);
        stop(&mut child).await;
        return Err(format!(
            "the new process did not report serving within {READY_WAIT:?}"
        ));
    }
    reply.ready_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    reply.draining_streams = live.streams.len();
    live.drain_after_upgrade();
    let _ = decide.send(true);
    Ok(())
}

fn exited(status: std::io::Result<std::process::ExitStatus>) -> String {
    match status {
        Ok(s) => format!("the new process exited before serving ({s}); see its log"),
        Err(e) => format!("the new process is gone: {e}"),
    }
}

/// Resolves once `path` exists.
async fn appears(path: &Path) {
    while !path.exists() {
        tokio::time::sleep(LISTEN_POLL).await;
    }
}

/// Kills the new process and reaps it.
async fn stop(child: &mut Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
}

/// Resolves once process `pid` connects to `ready`; others are ignored.
async fn reported(ready: &UnixListener, pid: u32) {
    loop {
        let Ok((stream, _)) = ready.accept().await else {
            continue;
        };
        let from = stream.peer_cred().ok().and_then(|c| c.pid());
        if from.and_then(|p| u32::try_from(p).ok()) == Some(pid) {
            return;
        }
        warn!("upgrade: ignored a ready report from pid {from:?}");
    }
}

/// Reports, once the relay accepts on its sockets, that this process serves: to the
/// process it took over from, to systemd, and in the pid file.
pub struct ReadyService {
    live: Arc<Live>,
    pidfile: Option<PathBuf>,
}

impl ReadyService {
    pub fn new(live: Arc<Live>, pidfile: Option<PathBuf>) -> Self {
        Self { live, pidfile }
    }
}

#[async_trait::async_trait]
impl ServiceWithDependents for ReadyService {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        _shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        ready.notify_ready();
        let mut listening = self.live.listening.clone();
        if listening.wait_for(|l| *l).await.is_err() {
            return;
        }
        if let Some(path) = &self.pidfile
            && let Err(e) = write_pidfile(path)
        {
            warn!("cannot write pid file {}: {e}", path.display());
        }
        let me = std::process::id();
        match (self.live.predecessor, self.live.ready_socket()) {
            (Some(old), Some(path)) => {
                match UnixStream::connect(&path).await {
                    Ok(mut s) => {
                        let _ = s.write_all(b"ready\n").await;
                        info!("serving; took over from pid {old}");
                        self.live.taken_over.send_replace(true);
                    }
                    Err(e) => warn!("cannot report to pid {old} at {}: {e}", path.display()),
                }
                notify(&format!("MAINPID={me}\nREADY=1"));
            }
            _ => notify("READY=1"),
        }
    }

    fn name(&self) -> &str {
        "ready"
    }

    fn runtime_group(&self) -> Option<&str> {
        Some(RUNTIME_GROUP)
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        Some(Vec::new())
    }
}

/// Tells systemd about this process when it runs as a `Type=notify` service; a
/// successor started by an upgrade inherits `NOTIFY_SOCKET` and announces itself as the
/// main process (`NotifyAccess=all`).
fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let bytes = path.as_encoded_bytes();
    let addr = match bytes.strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name),
        None => SocketAddr::from_pathname(&path),
    };
    let sent = addr.and_then(|a| UnixDatagram::unbound()?.send_to_addr(state.as_bytes(), &a));
    if let Err(e) = sent {
        warn!("cannot notify systemd: {e}");
    }
}

/// Writes this process's id to `path`, replacing it in one step.
fn write_pidfile(path: &Path) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}", std::process::id()));
    std::fs::write(&tmp, format!("{}\n", std::process::id()))?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// Removes the pid file if it still names this process, not a successor.
pub fn remove_pidfile(path: &Path) {
    let ours =
        std::fs::read_to_string(path).is_ok_and(|s| s.trim() == std::process::id().to_string());
    if ours && let Err(e) = std::fs::remove_file(path) {
        warn!("cannot remove pid file {}: {e}", path.display());
    }
}

/// Whether `pid` is a live process running the same program as this one.
pub(crate) fn runs_same_program(pid: u32) -> bool {
    let comm = |p: &str| std::fs::read(format!("/proc/{p}/comm")).ok();
    matches!((comm(&pid.to_string()), comm("self")), (Some(theirs), Some(ours)) if theirs == ours)
}

/// Passes a terminate signal on to the process this one took over from, which may still
/// be draining; only if that pid still runs the same program.
pub(crate) fn forward_terminate(pid: u32) {
    let Ok(raw) = i32::try_from(pid) else {
        return;
    };
    if runs_same_program(pid) {
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), nix::sys::signal::SIGTERM) {
            Ok(()) => info!("passed the terminate signal on to pid {pid}, which is draining"),
            Err(e) => warn!("cannot signal pid {pid}: {e}"),
        }
    }
}
