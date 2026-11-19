//! Upstream addresses in JSON bodies replaced by the relay's.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::{INFO_PUBLIC, Origin, SERVER_DOMAINS, gunzip, json_doc, unbrotli};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};

const ALIAS: &str = "alias.example.net";
const PLAYBACK_INFO: &str = "/emby/Items/1/PlaybackInfo";

type Decoder = fn(&[u8]) -> Vec<u8>;

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world(site_toml: &str) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let toml = format!("aliases = [\"{ALIAS}\"]\n{site_toml}");
    let relay = Relay::start(&RelaySetup {
        site_toml: &toml,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World { ca, origin, relay }
}

struct Reply {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", |v| v.to_str().unwrap())
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }
}

impl World {
    /// The site as the client addresses it.
    fn public(&self) -> String {
        format!("{SITE_HOST}:{}", self.relay.addr.port())
    }

    /// The origin as the relay addresses it.
    fn origin_host(&self) -> String {
        format!("{ORIGIN_HOST}:{}", self.origin.addr.port())
    }

    async fn send(&self, proto: Proto, method: &str, path: &str, ae: Option<&str>) -> Reply {
        let url = format!("https://{}{path}", self.public());
        let mut req = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, proto)
            .request(method.parse().unwrap(), url);
        if let Some(ae) = ae {
            req = req.header("accept-encoding", ae);
        }
        let res = req.send().await.unwrap();
        Reply {
            status: res.status().as_u16(),
            headers: res.headers().clone(),
            body: res.bytes().await.unwrap().to_vec(),
        }
    }

    /// `json_doc` after rewriting.
    fn rewritten_doc(&self) -> String {
        let p = self.public();
        format!(
            concat!(
                r#"{{"LocalAddress":"https://{p}","Url":"https://{p}/emby/x","#,
                r#""Esc":"https:\/\/{p}\/y","Rel":"//{p}/z","#,
                r#""Bare":"{site}","Other":"https://vod.example.net/a","#,
                r#""Near":"https://origin.example.net.evil.example/b","#,
                r#""Path":"/videos/1/stream?api_key=k"}}"#
            ),
            p = p,
            site = SITE_HOST,
        )
    }
}

#[tokio::test]
async fn info_local_address_points_at_the_relay() {
    let w = world("").await;
    let expected = INFO_PUBLIC.replace(
        &format!("https://{ORIGIN_HOST}"),
        &format!("https://{}", w.public()),
    );
    for proto in [Proto::H1, Proto::H2] {
        let r = w.send(proto, "GET", "/emby/System/Info/Public", None).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.text(), expected, "{proto:?}");
    }
}

#[tokio::test]
async fn playback_info_addresses_are_rewritten() {
    let w = world("").await;
    for proto in [Proto::H1, Proto::H2] {
        for method in ["GET", "POST"] {
            let r = w.send(proto, method, PLAYBACK_INFO, None).await;
            assert_eq!(r.status, 200);
            assert_eq!(r.text(), w.rewritten_doc(), "{proto:?} {method}");
            assert_eq!(r.header("x-seen-accept-encoding"), "identity");
            assert_eq!(r.header("etag"), "W/\"v1\"");
            assert_eq!(r.header("content-length"), "");
            if matches!(proto, Proto::H1) {
                // Chunked, not delimited by closing the connection.
                assert_eq!(r.header("transfer-encoding"), "chunked");
                assert_ne!(r.header("connection"), "close");
            }
        }
    }
}

#[tokio::test]
async fn rewritten_bodies_are_compressed_as_the_client_accepts() {
    let w = world("").await;
    let decoders: [(&str, Decoder); 2] = [("gzip", gunzip), ("br", unbrotli)];
    for proto in [Proto::H1, Proto::H2] {
        for (ae, decode) in decoders {
            let r = w.send(proto, "GET", PLAYBACK_INFO, Some(ae)).await;
            assert_eq!(r.header("content-encoding"), ae, "{proto:?}");
            assert_eq!(r.header("x-seen-accept-encoding"), "identity");
            assert!(
                r.header("vary")
                    .to_ascii_lowercase()
                    .contains("accept-encoding")
            );
            let body = String::from_utf8(decode(&r.body)).unwrap();
            assert_eq!(body, w.rewritten_doc(), "{proto:?} {ae}");
        }
    }
}

#[tokio::test]
async fn other_responses_pass_unchanged_and_keep_upstream_compression() {
    let w = world("").await;
    let r = w.send(Proto::H1, "GET", "/__json", None).await;
    assert_eq!(r.text(), json_doc(&w.origin_host(), 0));
    assert_eq!(r.header("etag"), "\"v1\"");
    let r = w.send(Proto::H2, "GET", "/__json", Some("gzip")).await;
    assert_eq!(r.header("x-seen-accept-encoding"), "gzip");
}

#[tokio::test]
async fn oversized_bodies_pass_unchanged() {
    let w = world("").await;
    let pad = 5 << 20;
    for proto in [Proto::H1, Proto::H2] {
        let r = w
            .send(proto, "GET", &format!("{PLAYBACK_INFO}?pad={pad}"), None)
            .await;
        assert_eq!(r.status, 200);
        assert!(
            r.body == json_doc(&w.origin_host(), pad).as_bytes(),
            "{proto:?}"
        );
    }
}

#[tokio::test]
async fn compressed_upstream_bodies_pass_unchanged() {
    let w = world("").await;
    let r = w
        .send(
            Proto::H1,
            "GET",
            &format!("{PLAYBACK_INFO}?gzip=1"),
            Some("gzip"),
        )
        .await;
    assert_eq!(r.header("content-encoding"), "gzip");
    assert_eq!(
        String::from_utf8(gunzip(&r.body)).unwrap(),
        json_doc(&w.origin_host(), 0)
    );
}

#[tokio::test]
async fn server_domains_follow_the_site_setting() {
    let path = "/emby/System/Ext/ServerDomains";
    let w = world("").await;
    let r = w.send(Proto::H1, "GET", path, None).await;
    assert_eq!(
        r.text(),
        format!(r#"{{"Domains":["{SITE_HOST}","{SITE_HOST}"]}}"#)
    );
    let w = world("server_domains = \"block\"").await;
    let r = w.send(Proto::H1, "GET", path, None).await;
    assert_eq!(r.status, 404);
    assert_eq!(w.origin.requests(), 0);
    let w = world("server_domains = \"pass\"").await;
    let r = w.send(Proto::H2, "GET", path, None).await;
    assert_eq!(r.text(), SERVER_DOMAINS);
}
