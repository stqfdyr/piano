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
}

pub struct Relay {
    pub addr: SocketAddr,
    live: Arc<Live>,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
    dir: TempDir,
    generation: AtomicU32,
}

struct StopSignal(watch::Receiver<bool>);

#[async_trait]
impl ShutdownSignalWatch for StopSignal {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.0.clone();
        let _ = rx.wait_for(|stop| *stop).await;
        ShutdownSignal::FastShutdown
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
        shutdown_timeout = "1s"

        [tls]
        cert = {cert:?}
        key = {key:?}

        [access]
        allow = [{allow}]

        [upstream]
        connect_timeout = "2s"
        read_timeout = "5s"
        extra_roots = [{roots}]

        {sites}
        "#,
        allow = allow.join(", "),
        roots = roots.join(", "),
    )
}

impl Relay {
    pub fn start(setup: &RelaySetup<'_>) -> Self {
        let dir = TempDir::new();
        let port = free_port();
        let config = piano_config::parse(&config_text(setup, &dir, 0, port)).unwrap();
        let resolver = Resolver::system().with_override(ORIGIN_HOST, IpAddr::from([127, 0, 0, 1]));
        let piano::Daemon { server, live } = piano::build(&config, resolver).unwrap();

        let (stop, rx) = watch::channel(false);
        let thread = std::thread::spawn(move || {
            server.run(RunArgs {
                shutdown_signal: Box::new(StopSignal(rx)),
            });
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

    pub fn denied_connections(&self) -> u64 {
        self.live.denied_connections()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
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
