//! Upstream attempts repeated before the response starts: only when no upstream answered.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::net::IpAddr;

struct World {
    ca: Ca,
    _origin: Origin,
    relay: Relay,
}

/// The origin listens on 127.0.0.1 only; the relay resolves its name to `ips`.
async fn world(ips: &[IpAddr]) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        origin_ips: ips,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World {
        ca,
        _origin: origin,
        relay,
    }
}

impl World {
    async fn send(&self, proto: Proto, method: &str, path: &str) -> (u16, String) {
        let url = format!("https://{SITE_HOST}:{}{path}", self.relay.addr.port());
        let res = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, proto)
            .request(method.parse().unwrap(), url)
            .send()
            .await
            .unwrap();
        (res.status().as_u16(), res.text().await.unwrap())
    }
}

fn ip(last: u8) -> IpAddr {
    IpAddr::from([127, 0, 0, last])
}

#[tokio::test]
async fn upstream_error_statuses_are_passed_on_without_retrying() {
    let w = world(&[]).await;
    for proto in [Proto::H1, Proto::H2] {
        for code in [500, 502, 503, 504] {
            let path = format!("/__seq/{proto:?}-{code}/{code},200");
            assert_eq!(w.send(proto, "GET", &path).await, (code, "1".into()));
        }
    }
}

#[tokio::test]
async fn refused_connection_moves_to_the_next_address() {
    // Nothing listens on 127.0.0.2 or 127.0.0.3.
    let w = world(&[ip(2), ip(3), ip(1)]).await;
    for i in 1..=3 {
        let path = format!("/__seq/next-{i}/200");
        assert_eq!(w.send(Proto::H1, "GET", &path).await, (200, "1".into()));
    }
    let l = &w.relay.access_lines(ACCESS_LOG, 1)[0];
    let port = w._origin.addr.port();
    let up: Vec<(String, Option<&str>, Option<u64>)> = l["up"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let addr = a["addr"].as_str().unwrap().to_owned();
            (addr, a["error"].as_str(), a["status"].as_u64())
        })
        .collect();
    let want = [
        (format!("127.0.0.2:{port}"), Some("ConnectRefused"), None),
        (format!("127.0.0.3:{port}"), Some("ConnectRefused"), None),
        (format!("127.0.0.1:{port}"), None, Some(200)),
    ];
    assert_eq!(up, want, "{l}");
    assert_eq!(l["end"], "ok", "{l}");
}

#[tokio::test]
async fn connection_retries_are_bounded_and_the_working_address_is_kept() {
    let w = world(&[ip(2), ip(3), ip(4), ip(1)]).await;
    // Two retries reach 127.0.0.4 at most; the request fails, but the next one
    // starts from 127.0.0.1 and so does every one after it.
    let (code, _) = w.send(Proto::H1, "GET", "/__seq/bounded-0/200").await;
    assert_eq!(code, 502);
    let l = &w.relay.access_lines(ACCESS_LOG, 1)[0];
    assert_eq!(l["end"], "connect_failed", "{l}");
    assert_eq!(l["status"], 502, "{l}");
    assert_eq!(l["up"].as_array().unwrap().len(), 3, "{l}");
    for i in 1..=3 {
        let path = format!("/__seq/bounded-{i}/200");
        assert_eq!(w.send(Proto::H2, "GET", &path).await, (200, "1".into()));
    }
}

#[tokio::test]
async fn post_is_retried_after_a_refused_connection() {
    let w = world(&[ip(2), ip(1)]).await;
    assert_eq!(
        w.send(Proto::H1, "POST", "/__seq/post-connect/200").await,
        (200, "1".into())
    );
}
