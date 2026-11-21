//! piano running in-process on its own threads.

use crate::{ORIGIN_HOST, TempDir, free_port, loopback};
use async_trait::async_trait;
use piano::{Live, RunArgs, ShutdownSignal, ShutdownSignalWatch};
use piano_upstream::Resolver;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What the relay under test trusts and serves.
pub struct RelaySetup<'a> {
    /// Certificate and key for the public sites.
    pub site: &'a crate::pki::Leaf,
    /// Extra upstream roots, PEM encoded.
    pub extra_roots: &'a [String],
    /// Port the fake origin listens on.
    pub origin_port: u16,
    /// `access.allow` entries.
    pub allow: &'a [&'a str],
    /// Public hosts, each relayed to the fake origin.
    pub hosts: &'a [&'a str],
    /// `block` entries for every site.
    pub block: &'a [&'a str],
    /// Extra TOML appended to every `[[site]]` table (may open `[[site.ua]]` tables).
    pub site_toml: &'a str,
    /// Further host names the relay resolves to loopback, like the origin's.
    pub names: &'a [&'a str],
    /// Addresses the relay resolves the origin's name to, in order; empty means
    /// loopback only.
    pub origin_ips: &'a [IpAddr],
    /// File name of the access log in the relay's directory; empty turns it off.
    pub access_log: &'a str,
    /// Lines of the `[limits]` table.
    pub limits: &'a str,
    /// `upstream.read_timeout`: short, so that stall tests end quickly.
    pub read_timeout: Duration,
    /// Serve the control socket, with the configuration written to a file for reloads.
    pub control: bool,
}

impl<'a> RelaySetup<'a> {
    /// One site, `SITE_HOST`, open to loopback, without extra rules.
    pub fn new(site: &'a crate::pki::Leaf, extra_roots: &'a [String], origin_port: u16) -> Self {
        Self {
            site,
            extra_roots,
            origin_port,
            allow: &["127.0.0.1"],
            hosts: &[crate::SITE_HOST],
            block: &[],
            site_toml: "",
            names: &[],
            origin_ips: &[],
            access_log: ACCESS_LOG,
            limits: "",
            read_timeout: Duration::from_secs(5),
            control: false,
        }
    }
}

/// The relay's `server.shutdown_timeout`.
pub const SHUTDOWN_TIMEOUT_SECS: u64 = 3;

/// Default access log file name.
pub const ACCESS_LOG: &str = "access.log";

/// File names of the control socket and configuration in the relay's directory.
pub const CONTROL_SOCKET: &str = "ctl.sock";
pub const CONFIG_FILE: &str = "piano.toml";
/// File name of the traffic record in the relay's directory.
pub const TRAFFIC_FILE: &str = "traffic.json";

pub struct Relay {
    pub addr: SocketAddr,
    live: Arc<Live>,
    stop: watch::Sender<Option<Stop>>,
    thread: Option<JoinHandle<()>>,
    dir: TempDir,
    generation: AtomicU32,
}

/// How the relay is told to stop.
#[derive(Clone, Copy)]
enum Stop {
    /// As on SIGINT: everything ends at once.
    Fast,
    /// As on SIGTERM.
    Terminate,
}

struct StopSignal(watch::Receiver<Option<Stop>>);

#[async_trait]
impl ShutdownSignalWatch for StopSignal {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.0.clone();
        let stop = rx.wait_for(Option::is_some).await.ok().and_then(|s| *s);
        match stop {
            Some(Stop::Terminate) => ShutdownSignal::GracefulTerminate,
            _ => ShutdownSignal::FastShutdown,
        }
    }
}

/// Writes the files `setup` needs into `dir` (names suffixed with `tag`) and returns
/// the configuration text listening on `port`.
fn config_text(setup: &RelaySetup<'_>, dir: &TempDir, tag: u32, port: u16) -> String {
    let cert = dir.write(&format!("site{tag}.crt"), &setup.site.cert_pem);
    let key = dir.write(&format!("site{tag}.key"), &setup.site.key_pem);
    let roots: Vec<String> = setup
        .extra_roots
        .iter()
        .enumerate()
        .map(|(i, pem)| format!("{:?}", dir.write(&format!("root{i}.pem"), pem)))
        .collect();
    let allow: Vec<String> = setup.allow.iter().map(|a| format!("{a:?}")).collect();
    let block: Vec<String> = setup.block.iter().map(|b| format!("{b:?}")).collect();
    let block = block.join(", ");
    let access_log = if setup.access_log.is_empty() {
        std::path::PathBuf::new()
    } else {
        dir.path().join(setup.access_log)
    };
    let sites: String = setup
        .hosts
        .iter()
        .map(|h| {
            format!(
                "[[site]]\nhost = \"{h}\"\nupstream = \"https://{ORIGIN_HOST}:{}\"\nblock = [{block}]\n{}\n",
                setup.origin_port, setup.site_toml
            )
        })
        .collect();
    format!(
        r#"
        [server]
        listen = ["127.0.0.1:{port}"]
        threads = 1
        shutdown_timeout = "{SHUTDOWN_TIMEOUT_SECS}s"

        [tls]
        cert = {cert:?}
        key = {key:?}

        [access]
        allow = [{allow}]
        # Loopback follows the list, so a test can be refused.
        loopback = false

        [upstream]
        connect_timeout = "2s"
        read_timeout = "{read_timeout}ms"
        extra_roots = [{roots}]

        [log]
        access = {access_log:?}

        [limits]
        {limits}

        [control]
        socket = {socket:?}

        [traffic]
        file = {traffic:?}

        {sites}
        "#,
        socket = dir.path().join(CONTROL_SOCKET),
        traffic = dir.path().join(TRAFFIC_FILE),
        allow = allow.join(", "),
        roots = roots.join(", "),
        limits = setup.limits,
        read_timeout = setup.read_timeout.as_millis(),
    )
}

impl Relay {
    pub fn start(setup: &RelaySetup<'_>) -> Self {
        let dir = TempDir::new();
        let port = free_port();
        let text = config_text(setup, &dir, 0, port);
        let config_path = dir.write(CONFIG_FILE, &text);
        let config = piano_config::parse(&text).unwrap();
        let local = [IpAddr::from([127, 0, 0, 1])];
        let origin_ips = if setup.origin_ips.is_empty() {
            &local
        } else {
            setup.origin_ips
        };
        let resolver = setup
            .names
            .iter()
            .fold(Resolver::system(), |r, name| r.with_override(name, &local))
            .with_override(ORIGIN_HOST, origin_ips);
        let piano::Daemon { mut server, live } = piano::build(&config, resolver).unwrap();
        if setup.control {
            let bound = piano_ctl::server::bind(&dir.path().join(CONTROL_SOCKET)).unwrap();
            let admin = piano::Admin::new(Arc::clone(&live), config_path, None);
            server.add_service(piano::ControlService::new(admin, bound));
        }

        let (stop, rx) = watch::channel(None);
        let thread = std::thread::spawn({
            let live = Arc::clone(&live);
            move || {
                server.run(RunArgs {
                    shutdown_signal: live.signals(Box::new(StopSignal(rx))),
                });
                live.stopped();
            }
        });
        let addr = loopback(port);
        wait_listening(addr);
        Self {
            addr,
            live,
            stop,
            thread: Some(thread),
            dir,
            generation: AtomicU32::new(1),
        }
    }

    /// Applies a new configuration built from `setup`, as a reload would. Returns the
    /// settings that would need a restart.
    pub fn reload(&self, setup: &RelaySetup<'_>) -> Result<Vec<&'static str>, piano::Error> {
        let tag = self.generation.fetch_add(1, Ordering::Relaxed);
        let text = config_text(setup, &self.dir, tag, self.addr.port());
        self.live.apply(&piano_config::parse(&text)?)
    }

    /// Rewrites the configuration file from `setup`, for a reload through the control
    /// socket to pick up.
    pub fn write_config(&self, setup: &RelaySetup<'_>) {
        let tag = self.generation.fetch_add(1, Ordering::Relaxed);
        let text = config_text(setup, &self.dir, tag, self.addr.port());
        self.dir.write(CONFIG_FILE, &text);
    }

    /// Writes `text` as the configuration file.
    pub fn write_config_text(&self, text: &str) {
        self.dir.write(CONFIG_FILE, text);
    }

    pub fn config_path(&self) -> std::path::PathBuf {
        self.dir.path().join(CONFIG_FILE)
    }

    /// The configuration file as written last.
    pub fn config(&self) -> piano_config::Config {
        piano_config::load(&self.dir.path().join(CONFIG_FILE)).unwrap()
    }

    pub fn control_socket(&self) -> std::path::PathBuf {
        self.dir.path().join(CONTROL_SOCKET)
    }

    /// Overwrites the certificate files the relay was started with, as a renewal would.
    pub fn replace_cert(&self, leaf: &crate::pki::Leaf) {
        self.dir.write("site0.crt", &leaf.cert_pem);
        self.dir.write("site0.key", &leaf.key_pem);
    }

    /// Runs the periodic certificate check now.
    pub fn refresh_certs(&self) -> Result<bool, piano::Error> {
        self.live.refresh_certs()
    }

    /// Why the last certificate check could not load the changed files.
    pub fn cert_reload_error(&self) -> Option<String> {
        self.live.cert_reload_error()
    }

    pub fn denied_connections(&self) -> u64 {
        self.live.denied_connections()
    }

    /// Writes the traffic record now, as the daemon does once a minute.
    pub fn record_traffic(&self) {
        self.live.record_traffic();
    }

    /// Writes the traffic record now and reads it back.
    pub fn traffic(&self) -> piano::traffic::Record {
        self.record_traffic();
        piano::traffic::read(&self.dir.path().join(TRAFFIC_FILE))
            .unwrap()
            .unwrap_or_default()
    }

    /// Path of access log file `name` in the relay's directory.
    pub fn log_path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    pub fn reopen_access_log(&self) {
        self.live.reopen_access_log().unwrap();
    }

    /// The lines of access log file `name` once it has at least `n`: requests are logged
    /// just after their response ends, so a client may get there first.
    pub fn access_lines(&self, name: &str, n: usize) -> Vec<serde_json::Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.live.flush_access_log();
            let text = std::fs::read_to_string(self.log_path(name)).unwrap_or_default();
            let lines: Vec<serde_json::Value> = text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
                .collect();
            if lines.len() >= n {
                return lines;
            }
            assert!(
                Instant::now() < deadline,
                "{name} has {} lines, expected {n}:\n{text}",
                lines.len()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The raw text of access log file `name` after a flush.
    pub fn access_text(&self, name: &str) -> String {
        self.live.flush_access_log();
        std::fs::read_to_string(self.log_path(name)).unwrap_or_default()
    }
}

impl Relay {
    /// Stops the relay as SIGTERM does and returns how long it took. Its files stay
    /// readable.
    pub fn terminate(&mut self) -> Duration {
        let started = Instant::now();
        let _ = self.stop.send(Some(Stop::Terminate));
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
        started.elapsed()
    }

    /// The text of access log file `name` once the relay has stopped.
    pub fn stopped_access_text(&self, name: &str) -> String {
        std::fs::read_to_string(self.log_path(name)).unwrap_or_default()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.stop.send(Some(Stop::Fast));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err() {
        assert!(
            Instant::now() < deadline,
            "relay did not start listening on {addr}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
