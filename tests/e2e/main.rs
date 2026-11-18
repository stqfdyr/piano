//! End-to-end: client → piano (TLS) → fake origin (TLS).

#![forbid(unsafe_code)]

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::{INFO_PUBLIC, Origin};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};

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
        let res = c
            .get(url(&w, "/emby/System/Info/Public"))
            .send()
            .await
            .unwrap();
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
