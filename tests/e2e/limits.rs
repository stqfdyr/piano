//! Bounds on client connections, mounted upstream hosts and certificate renewal.

use piano_e2e::client::{Proto, client, connect, connect_tcp, read_response};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const VOD: &str = "vod1.example.net";

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world(limits: &str, site_toml: &str) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST, VOD])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        limits,
        site_toml,
        names: &[VOD],
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World { ca, origin, relay }
}

/// Reads until the peer closes the connection; returns how long that took.
async fn time_to_close(io: &mut (impl AsyncRead + Unpin), limit: Duration) -> Duration {
    let start = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(limit, io.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return start.elapsed(),
            Ok(Ok(_)) => {}
            Err(_) => panic!("connection still open after {limit:?}"),
        }
    }
}

const GET_INFO: &[u8] = b"GET /__info HTTP/1.1\r\nhost: media.example.com\r\n\r\n";

#[tokio::test]
async fn idle_http1_connection_is_closed_after_the_keepalive_timeout() {
    let w = world("keepalive_timeout = \"2s\"", "").await;
    let mut tls = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    // Within the timeout the connection serves further requests, the first and every
    // later wait alike.
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        tls.write_all(GET_INFO).await.unwrap();
        let (head, _) = read_response(&mut tls).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    }
    let idle = time_to_close(&mut tls, Duration::from_secs(5)).await;
    assert!(idle > Duration::from_millis(1500), "{idle:?}");
}

#[tokio::test]
async fn idle_http2_connection_is_closed_after_the_keepalive_timeout() {
    let w = world("keepalive_timeout = \"2s\"", "").await;
    let mut tls = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H2).await;
    // Connection preface and an empty SETTINGS frame.
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
        .await
        .unwrap();
    let idle = time_to_close(&mut tls, Duration::from_secs(5)).await;
    assert!(idle > Duration::from_millis(1500), "{idle:?}");
}

#[tokio::test]
async fn a_stalled_request_head_is_cut_off_before_the_keepalive_timeout() {
    let w = world("keepalive_timeout = \"60s\"", "").await;
    let mut tls = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    tls.write_all(b"GET /__info HTTP/1.1\r\nhost: media")
        .await
        .unwrap();
    let t = time_to_close(&mut tls, Duration::from_secs(20)).await;
    assert!(t >= Duration::from_secs(9), "{t:?}");
    assert_eq!(w.origin.requests(), 0);
}

#[tokio::test]
async fn a_silent_connection_is_closed_after_the_handshake_timeout() {
    let w = world("handshake_timeout = \"1s\"", "").await;
    let mut tcp = connect_tcp(w.relay.addr).await;
    let t = time_to_close(&mut tcp, Duration::from_secs(5)).await;
    assert!(t > Duration::from_millis(800), "{t:?}");
}

#[tokio::test]
async fn connections_over_the_limit_are_closed_at_once() {
    let w = world("max_connections = 2", "").await;
    let a = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    let _b = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    let mut over = connect_tcp(w.relay.addr).await;
    let t = time_to_close(&mut over, Duration::from_secs(2)).await;
    assert!(t < Duration::from_secs(1), "{t:?}");
    drop(a);
    // The slot is given back once the relay notices the close.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
            .get(format!(
                "https://{SITE_HOST}:{}/__info",
                w.relay.addr.port()
            ))
            .send()
            .await;
        if res.is_ok_and(|r| r.status() == 200) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no slot after closing a connection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn mounted_prefix_goes_to_its_host_without_the_prefix() {
    let w = world("", "mounts = { \"/__m/vod1\" = \"vod1.example.net\" }").await;
    for proto in [Proto::H1, Proto::H2] {
        let body = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto)
            .get(format!(
                "https://{SITE_HOST}:{}/__M/vod1/__echo/a%20b?api_key=k",
                w.relay.addr.port()
            ))
            .header("x-emby-token", "t")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let port = w.origin.addr.port();
        assert!(
            body.lines().any(|l| l == format!("host: {VOD}:{port}")),
            "{body}"
        );
        let request_line = body.lines().next().unwrap_or_default();
        assert!(
            request_line.contains(" /__echo/a%20b?api_key=k ")
                || request_line.contains(":{port}/__echo/a%20b?api_key=k "),
            "{body}"
        );
        // A host of the upstream service gets the client's credentials.
        assert!(body.lines().any(|l| l == "x-emby-token: t"), "{body}");
    }
    let l = &w.relay.access_lines(ACCESS_LOG, 2)[0];
    assert_eq!(l["up"][0]["host"], VOD, "{l}");
}

#[tokio::test]
async fn renewed_certificate_files_are_picked_up() {
    let w = world("", "").await;
    assert!(!w.relay.refresh_certs().unwrap());
    let renewed = Ca::new("renewed");
    w.relay.replace_cert(&renewed.leaf(&[SITE_HOST]));
    assert!(w.relay.refresh_certs().unwrap());
    assert!(!w.relay.refresh_certs().unwrap());
    let url = format!("https://{SITE_HOST}:{}/__info", w.relay.addr.port());
    let res = client(renewed.cert_der(), SITE_HOST, w.relay.addr, Proto::H2)
        .get(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let old = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H2)
        .get(&url)
        .send()
        .await;
    assert!(old.is_err());
}

#[tokio::test]
async fn half_written_certificate_files_keep_the_current_one() {
    let w = world("", "").await;
    let renewed = Ca::new("renewed");
    let leaf = renewed.leaf(&[SITE_HOST]);
    // The chain is new but the key still the old one, as between two renames.
    w.relay.replace_cert(&leaf);
    let old_key = w.ca.leaf(&[SITE_HOST]);
    std::fs::write(w.relay.log_path("site0.key"), &old_key.key_pem).unwrap();
    assert!(w.relay.refresh_certs().is_err());
    let error = w
        .relay
        .cert_reload_error()
        .expect("the failure is kept for status");
    assert!(error.contains("site0.key"), "{error}");
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .get(format!(
            "https://{SITE_HOST}:{}/__info",
            w.relay.addr.port()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    std::fs::write(w.relay.log_path("site0.key"), &leaf.key_pem).unwrap();
    assert!(w.relay.refresh_certs().unwrap());
    assert_eq!(w.relay.cert_reload_error(), None);
}

#[tokio::test]
async fn restored_certificate_files_clear_the_reload_error() {
    let w = world("", "").await;
    let paths = ["site0.crt", "site0.key"].map(|f| w.relay.log_path(f));
    let saved = paths.clone().map(|p| {
        let modified = std::fs::metadata(&p).unwrap().modified().unwrap();
        (std::fs::read(&p).unwrap(), modified)
    });
    std::fs::write(&paths[1], "not a key").unwrap();
    assert!(w.relay.refresh_certs().is_err());
    assert!(w.relay.cert_reload_error().is_some());
    // Put back as `mv` from a backup would: same bytes, same modification time.
    for (p, (bytes, modified)) in paths.iter().zip(saved) {
        std::fs::write(p, bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }
    assert!(!w.relay.refresh_certs().unwrap());
    assert_eq!(w.relay.cert_reload_error(), None);
}
