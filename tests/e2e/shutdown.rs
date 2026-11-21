//! SIGTERM: requests in progress finish, media streams and websockets end at once, and
//! the relay exits as soon as no client connection is left.

use piano_e2e::client::{Proto, client, connect, read_head};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup, SHUTDOWN_TIMEOUT_SECS};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct World {
    ca: Ca,
    _origin: Origin,
    relay: Relay,
}

async fn world() -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
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

impl World {
    fn client(&self, proto: Proto) -> reqwest::Client {
        client(self.ca.cert_der(), SITE_HOST, self.relay.addr, proto)
    }

    fn url(&self, path: &str) -> String {
        format!("https://{SITE_HOST}:{}{path}", self.relay.addr.port())
    }
}

/// Terminates the relay on a blocking thread after `after`; returns it with the time
/// the shutdown took.
fn terminate_after(
    mut relay: Relay,
    after: Duration,
) -> tokio::task::JoinHandle<(Relay, Duration)> {
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(after);
        let took = relay.terminate();
        (relay, took)
    })
}

fn log_lines(relay: &Relay) -> Vec<serde_json::Value> {
    relay
        .stopped_access_text(ACCESS_LOG)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

const PROMPT: Duration = Duration::from_millis(1000);

/// A slow request (its head comes after 1 s) is in progress when the signal comes.
async fn finishes_in_progress(proto: Proto) {
    let w = world().await;
    let c = w.client(proto);
    let res = tokio::spawn(c.get(w.url("/__file/slow?len=1000&plan=h1000")).send());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let World {
        ca: _ca,
        _origin,
        relay,
    } = w;
    let stopping = terminate_after(relay, Duration::ZERO);
    let res = res.await.unwrap().unwrap();
    assert_eq!(res.status(), 200, "{proto:?}");
    assert_eq!(res.bytes().await.unwrap().len(), 1000, "{proto:?}");
    let (relay, took) = stopping.await.unwrap();
    assert!(took >= Duration::from_millis(500), "{proto:?}: {took:?}");
    assert!(
        took < Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
        "{proto:?}: waited for the timeout: {took:?}"
    );
    let lines = log_lines(&relay);
    assert_eq!(lines.len(), 1, "{proto:?}: {lines:?}");
    assert_eq!(lines[0]["end"], "ok", "{}", lines[0]);
    assert_eq!(lines[0]["status"], 200, "{}", lines[0]);
}

#[tokio::test]
async fn an_h1_request_in_progress_finishes_before_the_relay_exits() {
    finishes_in_progress(Proto::H1).await;
}

#[tokio::test]
async fn an_h2_request_in_progress_finishes_before_the_relay_exits() {
    finishes_in_progress(Proto::H2).await;
}

#[tokio::test]
async fn idle_connections_do_not_hold_the_shutdown_back() {
    let w = world().await;
    let h1 = w.client(Proto::H1);
    let h2 = w.client(Proto::H2);
    for c in [&h1, &h2] {
        assert_eq!(c.get(w.url("/__info")).send().await.unwrap().status(), 200);
    }
    let mut raw = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    let World {
        ca: _ca,
        _origin,
        relay,
    } = w;
    let (_relay, took) = terminate_after(relay, Duration::ZERO).await.unwrap();
    assert!(took < PROMPT, "{took:?}");
    // The idle connection was closed, not left to the client.
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut b))
        .await
        .expect("idle connection left open");
    assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
}

#[tokio::test]
async fn a_media_stream_ends_at_once() {
    let w = world().await;
    let c = w.client(Proto::H1);
    // The upstream pauses for longer than the whole test after 100 kB.
    let mut res = c
        .get(w.url("/videos/m/stream.mkv?len=10000000&plan=s100000:60000"))
        .header("range", "bytes=0-")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 206);
    let mut got = 0;
    while got < 100_000 {
        got += res.chunk().await.unwrap().unwrap().len();
    }
    let World {
        ca: _ca,
        _origin,
        relay,
    } = w;
    let (relay, took) = terminate_after(relay, Duration::ZERO).await.unwrap();
    assert!(took < PROMPT, "{took:?}");
    let rest = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match res.chunk().await {
                Ok(Some(_)) => {}
                other => return other.map(|_| ()),
            }
        }
    })
    .await
    .expect("stream left open");
    assert!(rest.is_err(), "the cut stream looked complete");
    let lines = log_lines(&relay);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["class"], "media", "{}", lines[0]);
    assert_eq!(lines[0]["end"], "shutdown", "{}", lines[0]);
    assert_eq!(lines[0]["bytes_out"], 100_000, "{}", lines[0]);
}

#[tokio::test]
async fn a_websocket_ends_at_once() {
    let w = world().await;
    let mut io = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    let req = format!(
        "GET /embywebsocket?api_key=k&deviceId=d HTTP/1.1\r\nhost: {SITE_HOST}\r\n\
         upgrade: websocket\r\nconnection: Upgrade\r\n\
         sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await.unwrap();
    io.flush().await.unwrap();
    let head = read_head(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let World {
        ca: _ca,
        _origin,
        relay,
    } = w;
    let (relay, took) = terminate_after(relay, Duration::ZERO).await.unwrap();
    assert!(took < PROMPT, "{took:?}");
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(2), io.read(&mut b))
        .await
        .expect("websocket left open");
    assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
    let lines = log_lines(&relay);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["class"], "socket", "{}", lines[0]);
    assert_eq!(lines[0]["status"], 101, "{}", lines[0]);
    assert_eq!(lines[0]["end"], "shutdown", "{}", lines[0]);
}

#[tokio::test]
async fn a_stuck_request_is_cut_at_the_shutdown_timeout() {
    let w = world().await;
    let c = w.client(Proto::H1);
    // The head comes after the shutdown timeout but before the upstream read timeout.
    let res = tokio::spawn(c.get(w.url("/__file/stuck?len=10&plan=h4500")).send());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let World {
        ca: _ca,
        _origin,
        relay,
    } = w;
    let (_relay, took) = terminate_after(relay, Duration::ZERO).await.unwrap();
    let timeout = Duration::from_secs(SHUTDOWN_TIMEOUT_SECS);
    assert!(took >= timeout - Duration::from_millis(100), "{took:?}");
    assert!(took < timeout + PROMPT, "{took:?}");
    assert!(
        res.await.unwrap().is_err(),
        "the stuck request got an answer"
    );
}
