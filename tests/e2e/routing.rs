//! Site selection and local answers.

use crate::read_response;
use piano_e2e::client::{Proto, client, connect};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use tokio::io::AsyncWriteExt;

const OTHER_HOST: &str = "other.example.com";

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world(block: &[&str]) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let relay = Relay::start(&RelaySetup {
        site: &ca.leaf(&[SITE_HOST, OTHER_HOST]),
        extra_roots: &[ca.cert_pem()],
        origin_port: origin.addr.port(),
        allow: &["127.0.0.1"],
        hosts: &[SITE_HOST, OTHER_HOST],
        block,
    });
    World { ca, origin, relay }
}

async fn get(w: &World, proto: Proto, path: &str) -> reqwest::Response {
    client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto)
        .get(format!("https://{SITE_HOST}:{}{path}", w.relay.addr.port()))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn health_is_answered_locally() {
    let w = world(&[]).await;
    for proto in [Proto::H1, Proto::H2] {
        let res = get(&w, proto, "/__piano/health").await;
        assert_eq!(res.status(), 200);
        assert_eq!(res.headers()["cache-control"], "no-store");
        assert_eq!(res.text().await.unwrap(), "ok\n");
    }
    assert_eq!(w.origin.requests(), 0);
}

#[tokio::test]
async fn blocked_paths_get_404_without_reaching_the_origin() {
    let w = world(&["/emby/api/danmu/"]).await;
    for path in ["/emby/api/danmu/1", "/API/Danmu/x?y=1", "/emby/api/danmu/"] {
        let res = get(&w, Proto::H2, path).await;
        assert_eq!(res.status(), 404, "{path}");
    }
    assert_eq!(w.origin.requests(), 0);
    assert_eq!(get(&w, Proto::H1, "/emby/api/danmuku").await.status(), 404);
    assert_eq!(w.origin.requests(), 1, "an unblocked path is relayed");
}

/// Sends requests for `hosts` in turn on one connection opened for SITE_HOST and
/// returns the status lines.
async fn statuses(w: &World, hosts: &[&str]) -> Vec<String> {
    let mut io = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    let mut out = Vec::new();
    for host in hosts {
        let req = format!("GET /emby/System/Info/Public HTTP/1.1\r\nhost: {host}\r\n\r\n");
        io.write_all(req.as_bytes()).await.unwrap();
        io.flush().await.unwrap();
        let (head, _) = read_response(&mut io).await;
        out.push(head.lines().next().unwrap_or_default().to_owned());
    }
    out
}

#[tokio::test]
async fn a_connection_serves_only_the_site_it_was_opened_for() {
    let w = world(&[]).await;
    // A wrong host ends the connection with 421, so it comes last.
    let got = statuses(&w, &["MEDIA.example.com:443", OTHER_HOST]).await;
    assert!(got[0].starts_with("HTTP/1.1 200"), "{got:?}");
    assert!(got[1].starts_with("HTTP/1.1 421"), "{got:?}");
    let got = statuses(&w, &["unknown.example.com"]).await;
    assert!(got[0].starts_with("HTTP/1.1 421"), "{got:?}");
    assert_eq!(w.origin.requests(), 1);
}

#[tokio::test]
async fn local_answers_keep_the_connection_open() {
    let w = world(&["/emby/api/danmu/"]).await;
    let mut io = connect(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1).await;
    for (path, status) in [
        ("/__piano/health", "200"),
        ("/emby/api/danmu/1", "404"),
        ("/emby/System/Info/Public", "200"),
    ] {
        let req = format!("GET {path} HTTP/1.1\r\nhost: {SITE_HOST}\r\n\r\n");
        io.write_all(req.as_bytes()).await.unwrap();
        io.flush().await.unwrap();
        let (head, _) = read_response(&mut io).await;
        assert!(
            head.starts_with(&format!("HTTP/1.1 {status}")),
            "{path}: {head}"
        );
    }
}
