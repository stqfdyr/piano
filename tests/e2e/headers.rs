//! Request and response header policy.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};

const SITE_TOML: &str = r#"cookies.strip = ["upstream_session"]
[[site.ua]]
match = '^$|(?i)^curl/'
set = "EmbyMini/0.1.0"
"#;

struct World {
    ca: Ca,
    _origin: Origin,
    relay: Relay,
}

async fn world() -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let relay = Relay::start(&RelaySetup {
        site: &ca.leaf(&[SITE_HOST]),
        extra_roots: &[ca.cert_pem()],
        origin_port: origin.addr.port(),
        allow: &["127.0.0.1"],
        hosts: &[SITE_HOST],
        block: &[],
        site_toml: SITE_TOML,
        names: &[],
        origin_ips: &[],
    });
    World {
        ca,
        _origin: origin,
        relay,
    }
}

fn url(w: &World, path: &str) -> String {
    format!("https://{SITE_HOST}:{}{path}", w.relay.addr.port())
}

/// The header lines the origin saw, lowercased names.
async fn echo(w: &World, proto: Proto, headers: &[(&str, &str)]) -> Vec<String> {
    let mut req = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto).get(url(w, "/__echo"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let body = req.send().await.unwrap().text().await.unwrap();
    body.lines().skip(1).map(str::to_owned).collect()
}

#[tokio::test]
async fn request_policy_hides_the_client_and_applies_site_rules() {
    let w = world().await;
    for proto in [Proto::H1, Proto::H2] {
        let lines = echo(
            &w,
            proto,
            &[
                ("x-forwarded-for", "192.0.2.1"),
                ("x-real-ip", "192.0.2.1"),
                ("cf-connecting-ip", "192.0.2.1"),
                ("forwarded", "for=192.0.2.1"),
                ("cookie", "a=1; upstream_session=x; b=2"),
                ("user-agent", "curl/8.5.0"),
            ],
        )
        .await;
        assert!(
            !lines.iter().any(|l| l.contains("192.0.2.1")),
            "{proto:?}: {lines:?}"
        );
        assert!(
            lines.contains(&"cookie: a=1; b=2".to_owned()),
            "{proto:?}: {lines:?}"
        );
        assert!(
            lines.contains(&"user-agent: EmbyMini/0.1.0".to_owned()),
            "{proto:?}: {lines:?}"
        );
    }
    let lines = echo(&w, Proto::H2, &[("user-agent", "SenPlayer/5.1")]).await;
    assert!(
        lines.contains(&"user-agent: SenPlayer/5.1".to_owned()),
        "{lines:?}"
    );
}

#[tokio::test]
async fn response_policy_hides_cdn_headers_and_moves_cookies() {
    let w = world().await;
    for proto in [Proto::H1, Proto::H2] {
        let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto);
        let res = c.get(url(&w, "/__cdn")).send().await.unwrap();
        let h = res.headers();
        for hidden in ["server", "cf-ray", "alt-svc", "via"] {
            assert!(h.get(hidden).is_none(), "{proto:?}: {hidden}");
        }
        assert_eq!(
            h["strict-transport-security"],
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(h["x-frame-options"], "SAMEORIGIN");
        let cookies: Vec<_> = h.get_all("set-cookie").iter().collect();
        assert_eq!(
            cookies,
            [
                format!("s=1; Path=/; Domain={SITE_HOST}").as_str(),
                "t=2; Path=/"
            ],
            "{proto:?}"
        );
    }
}

#[tokio::test]
async fn local_answers_carry_security_headers() {
    let w = world().await;
    let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1);
    let res = c.get(url(&w, "/__piano/health")).send().await.unwrap();
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
}
