//! Redirects followed inside the relay.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::{Origin, pattern_byte};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};

const VOD: &str = "vod.example.net";
const FILES: &str = "abc.files.example.net";
const ALIAS: &str = "alias.example.net";
const EVIL: &str = "evil.example.net";

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world() -> World {
    world_with(
        r#"aliases = ["alias.example.net"]
follow = ["vod.example.net", "*.files.example.net"]"#,
    )
    .await
}

/// A site with `site_toml` instead of the default follow rules.
async fn world_with(site_toml: &str) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST, VOD, FILES, ALIAS, EVIL])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        site_toml,
        // SITE_HOST too, so a redirect back to the site would really reach the relay.
        names: &[VOD, FILES, ALIAS, EVIL, SITE_HOST],
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World { ca, origin, relay }
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A path on the relay that the origin answers with a redirect to `to`.
fn redirect(to: &str, status: u16) -> String {
    format!("/__redirect?status={status}&to={}", encode(to))
}

impl World {
    fn port(&self) -> u16 {
        self.origin.addr.port()
    }

    fn get(&self, proto: Proto, path: &str) -> reqwest::RequestBuilder {
        client(self.ca.cert_der(), SITE_HOST, self.relay.addr, proto).get(format!(
            "https://{SITE_HOST}:{}{path}",
            self.relay.addr.port()
        ))
    }
}

async fn text(req: reqwest::RequestBuilder) -> (u16, String) {
    let res = req.send().await.unwrap();
    (res.status().as_u16(), res.text().await.unwrap())
}

#[tokio::test]
async fn follows_listed_hosts_keeping_path_bytes() {
    let w = world().await;
    let path = "/__echo/%E6%B5%8B%E8%AF%95.mkv?x=%2F&y=a%20b";
    for proto in [Proto::H1, Proto::H2] {
        for status in [301, 302, 303, 307, 308] {
            let to = format!("https://VOD.Example.net:{}{path}", w.port());
            let (code, body) = text(w.get(proto, &redirect(&to, status))).await;
            assert_eq!(code, 200, "{proto:?} {status}: {body}");
            let mut lines = body.lines();
            let line = lines
                .next()
                .and_then(|l| l.rsplit_once(' '))
                .map(|(l, _)| l);
            assert_eq!(line, Some(format!("GET {path}").as_str()), "{body}");
            let host = format!("host: {VOD}:{}", w.port());
            assert!(body.lines().any(|l| l == host), "{body}");
        }
    }
}

#[tokio::test]
async fn credentials_go_only_to_the_upstream_and_its_aliases() {
    let w = world().await;
    let port = w.port();
    for (to, credentials) in [
        ("/__echo".to_owned(), true),
        (format!("https://{ALIAS}:{port}/__echo"), true),
        (format!("https://{VOD}:{port}/__echo"), false),
    ] {
        let req = w
            .get(Proto::H2, &redirect(&to, 302))
            .header("cookie", "session=1")
            .header("x-emby-token", "secret")
            .header("authorization", "MediaBrowser Token=\"secret\"");
        let (code, body) = text(req).await;
        assert_eq!(code, 200, "{to}");
        for name in ["cookie:", "x-emby-token:", "authorization:"] {
            assert_eq!(
                body.lines().any(|l| l.starts_with(name)),
                credentials,
                "{to}: {name}\n{body}"
            );
        }
    }
}

#[tokio::test]
async fn a_follow_list_refuses_other_hosts_without_the_location() {
    let w = world().await;
    let port = w.port();
    for to in [
        format!("https://{EVIL}:{port}/__echo"),
        format!("https://x.y.files.example.net:{port}/__echo"),
        "https://192.0.2.1/x".to_owned(),
        "ftp://vod.example.net/x".to_owned(),
    ] {
        let res = w.get(Proto::H1, &redirect(&to, 302)).send().await.unwrap();
        assert_eq!(res.status(), 502, "{to}");
        assert!(res.headers().get("location").is_none(), "{to}");
        let body = res.text().await.unwrap();
        assert!(
            !body.contains("example.net") && !body.contains("192.0.2.1"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn without_a_follow_list_any_host_is_followed_but_not_back_into_the_relay() {
    let w = world_with(r#"aliases = ["alias.example.net"]"#).await;
    let port = w.port();
    for host in [EVIL, VOD] {
        let to = format!("https://{host}:{port}/__echo");
        let req = w
            .get(Proto::H1, &redirect(&to, 302))
            .header("x-emby-token", "secret");
        let (code, body) = text(req).await;
        assert_eq!(code, 200, "{to}");
        assert!(!body.contains("x-emby-token"), "{body}");
    }
    let to = format!("https://{SITE_HOST}:{}/__echo", w.relay.addr.port());
    let res = w.get(Proto::H1, &redirect(&to, 302)).send().await.unwrap();
    assert_eq!(res.status(), 502);
    assert!(res.headers().get("location").is_none());
}

#[tokio::test]
async fn a_location_outside_a_redirect_is_not_followed() {
    let w = world().await;
    for status in [201, 304] {
        let res = w
            .get(Proto::H1, &redirect("/__echo", status))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status);
    }
    for l in w.relay.access_lines(ACCESS_LOG, 2) {
        assert_eq!(l["up"].as_array().unwrap().len(), 1, "{l}");
    }
}

#[tokio::test]
async fn redirect_chains_are_capped() {
    let w = world().await;
    assert_eq!(
        text(w.get(Proto::H1, "/__loop/5")).await,
        (200, "done".into())
    );
    assert_eq!(text(w.get(Proto::H2, "/__loop/6")).await.0, 502);
}

#[tokio::test]
async fn ranges_survive_a_redirect_to_a_wildcard_host() {
    let w = world().await;
    let to = format!("https://ABC.files.example.net:{}/__bytes/1000", w.port());
    for proto in [Proto::H1, Proto::H2] {
        let res = w
            .get(proto, &redirect(&to, 302))
            .header("range", "bytes=10-19")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 206, "{proto:?}");
        assert_eq!(res.headers()["content-range"], "bytes 10-19/1000");
        let body = res.bytes().await.unwrap();
        assert!(body.iter().zip(10u64..).all(|(&b, i)| b == pattern_byte(i)));
    }
}

#[tokio::test]
async fn only_get_and_head_are_followed() {
    let w = world().await;
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .post(format!(
            "https://{SITE_HOST}:{}{}",
            w.relay.addr.port(),
            redirect("/__echo", 307)
        ))
        .body("x")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .head(format!(
            "https://{SITE_HOST}:{}{}",
            w.relay.addr.port(),
            redirect("/__echo", 302)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn access_log_shows_each_hop_and_why_a_redirect_was_refused() {
    let w = world().await;
    let port = w.port();
    let to = format!("https://{VOD}:{port}/__echo?api_key=s3cret");
    assert_eq!(text(w.get(Proto::H1, &redirect(&to, 302))).await.0, 200);
    for to in [
        format!("https://{EVIL}:{port}/__echo?api_key=s3cret"),
        "ftp://vod.example.net/x?api_key=s3cret".to_owned(),
        "https://user:pw0rd@192.0.2.1/x?sign=s3cret".to_owned(),
    ] {
        assert_eq!(text(w.get(Proto::H1, &redirect(&to, 302))).await.0, 502);
    }
    let lines = w.relay.access_lines(ACCESS_LOG, 4);

    let l = &lines[0];
    assert_eq!(l["end"], "ok", "{l}");
    let hops: Vec<(&str, u64)> = l["up"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["host"].as_str().unwrap(), a["status"].as_u64().unwrap()))
        .collect();
    assert_eq!(hops, [(ORIGIN_HOST, 302), (VOD, 200)], "{l}");

    for (l, reason) in lines[1..]
        .iter()
        .zip([EVIL, "scheme", "credentials: \"https://192.0.2.1\""])
    {
        assert_eq!(l["end"], "redirect_refused", "{l}");
        assert_eq!(l["status"], 502, "{l}");
        assert!(l["err"].as_str().unwrap().contains(reason), "{l}");
        assert_eq!(l["up"].as_array().unwrap().len(), 1, "{l}");
    }
    // The client's own path carries the Location percent-encoded, so the decoded forms
    // must appear nowhere: a refused Location shows its scheme and host only, since its
    // path, query and user info can carry signatures and passwords that redaction does
    // not recognise.
    let text = w.relay.access_text(ACCESS_LOG);
    for secret in ["api_key=s3cret", "sign=s3cret", "user:pw0rd"] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
}
