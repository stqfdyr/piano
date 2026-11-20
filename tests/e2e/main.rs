//! End-to-end: client → piano (TLS) → fake origin (TLS).

#![forbid(unsafe_code)]

mod access;
mod control;
mod follow;
mod headers;
mod images;
mod limits;
mod log;
mod media;
mod retry;
mod rewrite;
mod routing;
mod socket;

use piano_e2e::client::{Proto, client, connect};
use piano_e2e::origin::{INFO_PUBLIC, Origin, pattern_byte};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

/// A relay serving SITE_HOST in front of an origin whose certificate is issued by
/// `origin_ca`; the relay trusts `trusted_roots` on top of the system roots.
async fn world(origin_ca: Option<&Ca>, trust_origin_ca: bool) -> World {
    let ca = Ca::new("piano e2e");
    let origin_ca = origin_ca.unwrap_or(&ca);
    let origin = Origin::start(&origin_ca.leaf(&[ORIGIN_HOST])).await;
    let roots = if trust_origin_ca {
        vec![origin_ca.cert_pem()]
    } else {
        vec![]
    };
    let relay = Relay::start(&RelaySetup {
        site: &ca.leaf(&[SITE_HOST]),
        extra_roots: &roots,
        origin_port: origin.addr.port(),
        allow: &["127.0.0.1"],
        hosts: &[SITE_HOST],
        block: &[],
        site_toml: "",
        names: &[],
        origin_ips: &[],
        access_log: piano_e2e::relay::ACCESS_LOG,
        limits: "",
        control: false,
    });
    World { ca, origin, relay }
}

fn url(w: &World, path: &str) -> String {
    format!("https://{SITE_HOST}:{}{path}", w.relay.addr.port())
}

#[tokio::test]
async fn passes_through_200_over_h1_and_h2() {
    let w = world(None, true).await;
    for (proto, version) in [
        (Proto::H1, reqwest::Version::HTTP_11),
        (Proto::H2, reqwest::Version::HTTP_2),
    ] {
        let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto);
        let res = c.get(url(&w, "/__info")).send().await.unwrap();
        assert_eq!(res.status(), 200, "{proto:?}");
        assert_eq!(res.version(), version, "{proto:?}");
        assert_eq!(
            res.headers()["content-type"],
            "application/json; charset=utf-8"
        );
        assert_eq!(res.text().await.unwrap(), INFO_PUBLIC, "{proto:?}");
    }
    assert_eq!(w.origin.requests(), 2);
}

#[tokio::test]
async fn upstream_host_header_is_the_origin() {
    let w = world(None, true).await;
    let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1);
    let body = c
        .get(url(&w, "/__echo"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let expected = format!("host: {ORIGIN_HOST}:{}", w.origin.addr.port());
    assert!(body.lines().any(|l| l == expected), "{body}");
}

#[tokio::test]
async fn origin_status_is_passed_through() {
    let w = world(None, true).await;
    let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H2);
    let res = c.get(url(&w, "/no/such/path")).send().await.unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn unknown_sni_fails_the_handshake() {
    let w = world(None, true).await;
    let other = "other.example.com";
    let c = client(w.ca.cert_der(), other, w.relay.addr, Proto::H1);
    let err = c
        .get(format!("https://{other}:{}/", w.relay.addr.port()))
        .send()
        .await
        .unwrap_err();
    assert!(err.is_connect(), "{err:?}");
    assert_eq!(w.origin.requests(), 0);
}

#[tokio::test]
async fn untrusted_origin_certificate_is_a_502() {
    let rogue = Ca::new("rogue");
    let w = world(Some(&rogue), false).await;
    let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1);
    let res = c.get(url(&w, "/System/Info/Public")).send().await.unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(w.origin.requests(), 0);
}

#[tokio::test]
async fn range_requests_are_passed_through() {
    let w = world(None, true).await;
    for proto in [Proto::H1, Proto::H2] {
        let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto);
        let res = c
            .get(url(&w, "/__bytes/1000000"))
            .header("range", "bytes=1000-1999")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 206, "{proto:?}");
        assert_eq!(res.headers()["content-range"], "bytes 1000-1999/1000000");
        let body = res.bytes().await.unwrap();
        assert_eq!(body.len(), 1000);
        assert!(
            body.iter()
                .zip(1000u64..)
                .all(|(&b, i)| b == pattern_byte(i))
        );
    }
}

#[tokio::test]
async fn large_bodies_stream_intact() {
    const LEN: u64 = 64 << 20;
    let w = world(None, true).await;
    for proto in [Proto::H1, Proto::H2] {
        let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto);
        let mut res = c
            .get(url(&w, &format!("/__bytes/{LEN}")))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let mut offset = 0u64;
        while let Some(chunk) = res.chunk().await.unwrap() {
            assert!(
                chunk
                    .iter()
                    .zip(offset..)
                    .all(|(&b, i)| b == pattern_byte(i)),
                "{proto:?}: corrupt data near offset {offset}"
            );
            offset += chunk.len() as u64;
        }
        assert_eq!(offset, LEN, "{proto:?}");
    }
}

/// Reads one HTTP/1.1 response with a `content-length` body.
pub(crate) async fn read_response(io: &mut (impl AsyncRead + Unpin)) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed inside the response header");
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .expect("content-length");
    let mut body = buf.split_off(head_end);
    while body.len() < len {
        let mut chunk = [0u8; 4096];
        let n = io.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed inside the body");
        body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body.len(), len, "bytes beyond the body");
    (head, body)
}

#[tokio::test]
async fn keepalive_connection_serves_requests_in_turn() {
    let w = world(None, true).await;
    let mut io = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    for i in 0..3 {
        // The second request has a header far larger than one small read and arrives
        // in two pieces.
        let pad = if i == 1 {
            "a".repeat(3000)
        } else {
            String::new()
        };
        let req = format!("GET /__info HTTP/1.1\r\nhost: {SITE_HOST}\r\nx-pad: {pad}\r\n\r\n");
        if i == 1 {
            let (a, b) = req.as_bytes().split_at(10);
            io.write_all(a).await.unwrap();
            io.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            io.write_all(b).await.unwrap();
        } else {
            io.write_all(req.as_bytes()).await.unwrap();
        }
        io.flush().await.unwrap();
        let (head, body) = read_response(&mut io).await;
        assert!(head.starts_with("HTTP/1.1 200"), "request {i}: {head}");
        assert_eq!(body, INFO_PUBLIC.as_bytes(), "request {i}");
    }
    assert_eq!(w.origin.requests(), 3);
}
