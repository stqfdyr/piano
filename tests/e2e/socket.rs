//! The Emby websocket, relayed as an HTTP/1.1 upgrade.

use piano_e2e::SITE_HOST;
use piano_e2e::client::{Proto, connect, read_head};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct World {
    ca: Ca,
    _origin: Origin,
    relay: Relay,
}

async fn world() -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[piano_e2e::ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup::new(
        &ca.leaf(&[SITE_HOST]),
        &roots,
        origin.addr.port(),
    ));
    World {
        ca,
        _origin: origin,
        relay,
    }
}

async fn echo(io: &mut (impl AsyncRead + AsyncWrite + Unpin), msg: &[u8]) {
    io.write_all(msg).await.unwrap();
    io.flush().await.unwrap();
    let mut back = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut back))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(back, msg);
}

impl World {
    /// An upgraded connection through the relay.
    async fn open(&self) -> impl AsyncRead + AsyncWrite + Unpin {
        let mut io = connect(self.ca.cert_der(), SITE_HOST, self.relay.addr, Proto::H1).await;
        let req = format!(
            "GET /embywebsocket?api_key=k&deviceId=d HTTP/1.1\r\nhost: {SITE_HOST}\r\n\
             upgrade: websocket\r\nconnection: Upgrade\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
        );
        io.write_all(req.as_bytes()).await.unwrap();
        io.flush().await.unwrap();
        let head = read_head(&mut io).await.to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(head.contains("upgrade: websocket"), "{head}");
        io
    }
}

#[tokio::test]
async fn upgrade_relays_bytes_both_ways() {
    let w = world().await;
    let mut io = w.open().await;
    echo(&mut io, b"\x81\x05hello").await;
    echo(&mut io, &[7u8; 100_000]).await;
    drop(io);
    // Logged when the socket closes.
    let l = &w.relay.access_lines(ACCESS_LOG, 1)[0];
    assert_eq!(l["class"], "socket", "{l}");
    assert_eq!(l["status"], 101, "{l}");
    assert_eq!(
        l["path"], "/embywebsocket?api_key=REDACTED&deviceId=d",
        "{l}"
    );
    assert_eq!(l["up"][0]["status"], 101, "{l}");
    let record = w.relay.traffic();
    let site = record.days.values().next().unwrap()["media"];
    assert_eq!(site.sent.socket, 5 + 2 + 100_000, "{site:?}");
    assert_eq!(site.fetched.socket, 5 + 2 + 100_000, "{site:?}");
}

#[tokio::test]
async fn quiet_socket_outlives_the_upstream_read_timeout() {
    // The test relay's upstream read timeout is 5 s.
    let w = world().await;
    let mut io = w.open().await;
    echo(&mut io, b"before").await;
    tokio::time::sleep(Duration::from_secs(7)).await;
    echo(&mut io, b"after").await;
}

/// Slow: waits past the 60 s downstream read timeout that applies to other requests.
#[tokio::test]
#[ignore]
async fn quiet_socket_outlives_the_default_downstream_read_timeout() {
    let w = world().await;
    let mut io = w.open().await;
    tokio::time::sleep(Duration::from_secs(65)).await;
    echo(&mut io, b"after").await;
}
