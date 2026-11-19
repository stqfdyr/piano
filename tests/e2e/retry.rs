//! Upstream attempts repeated before the response starts.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
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
async fn bad_gateway_and_gateway_timeout_are_retried_once() {
    let w = world(&[]).await;
    for proto in [Proto::H1, Proto::H2] {
        for code in [502, 504] {
            let once = format!("/__seq/{proto:?}-once-{code}/{code},200");
            assert_eq!(w.send(proto, "GET", &once).await, (200, "2".into()));
            let twice = format!("/__seq/{proto:?}-twice-{code}/{code},{code},200");
            assert_eq!(w.send(proto, "GET", &twice).await, (code, "2".into()));
        }
    }
}

#[tokio::test]
async fn service_unavailable_is_not_retried() {
    let w = world(&[]).await;
    assert_eq!(
        w.send(Proto::H1, "GET", "/__seq/503/503,200").await,
        (503, "1".into())
    );
}

#[tokio::test]
async fn non_idempotent_requests_are_not_retried_on_status() {
    let w = world(&[]).await;
    assert_eq!(
        w.send(Proto::H1, "POST", "/__seq/post/502,200").await,
        (502, "1".into())
    );
}

#[tokio::test]
async fn refused_connection_moves_to_the_next_address() {
    // Nothing listens on 127.0.0.2 or 127.0.0.3.
    let w = world(&[ip(2), ip(3), ip(1)]).await;
    for i in 1..=3 {
        let path = format!("/__seq/next-{i}/200");
        assert_eq!(w.send(Proto::H1, "GET", &path).await, (200, "1".into()));
    }
}

#[tokio::test]
async fn connection_retries_are_bounded_and_the_working_address_is_kept() {
    let w = world(&[ip(2), ip(3), ip(4), ip(1)]).await;
    // Two retries reach 127.0.0.4 at most; the request fails, but the next one
    // starts from 127.0.0.1 and so does every one after it.
    let (code, _) = w.send(Proto::H1, "GET", "/__seq/bounded-0/200").await;
    assert_eq!(code, 502);
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
