//! piano running in-process on its own threads.

use crate::{ORIGIN_HOST, SITE_HOST, TempDir, free_port, loopback};
use async_trait::async_trait;
use piano::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
use piano_upstream::Resolver;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// What the relay under test trusts and serves.
pub struct RelaySetup<'a> {
    /// Certificate and key for the public site.
    pub site: &'a crate::pki::Leaf,
    /// Extra upstream roots, PEM encoded.
    pub extra_roots: &'a [String],
    /// Port the fake origin listens on.
    pub origin_port: u16,
}

pub struct Relay {
    pub addr: SocketAddr,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
    _dir: TempDir,
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

impl Relay {
    pub fn start(setup: &RelaySetup<'_>) -> Self {
        let dir = TempDir::new();
        let cert = dir.write("site.crt", &setup.site.cert_pem);
        let key = dir.write("site.key", &setup.site.key_pem);
        let roots: Vec<String> = setup
            .extra_roots
            .iter()
            .enumerate()
            .map(|(i, pem)| format!("{:?}", dir.write(&format!("root{i}.pem"), pem)))
            .collect();
        let port = free_port();
        let text = format!(
            r#"
            [server]
            listen = ["127.0.0.1:{port}"]
            threads = 1
            shutdown_timeout = "1s"

            [tls]
            cert = {cert:?}
            key = {key:?}

            [upstream]
            connect_timeout = "2s"
            read_timeout = "5s"
            extra_roots = [{roots}]

            [[site]]
            host = "{SITE_HOST}"
            upstream = "https://{ORIGIN_HOST}:{origin_port}"
            "#,
            roots = roots.join(", "),
            origin_port = setup.origin_port,
        );
        let config = piano_config::parse(&text).unwrap();
        let resolver = Resolver::system().with_override(ORIGIN_HOST, IpAddr::from([127, 0, 0, 1]));
        let server = piano::build_server(&config, &resolver).unwrap();

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
            stop,
            thread: Some(thread),
            _dir: dir,
        }
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
