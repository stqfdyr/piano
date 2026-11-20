//! Upstream HTTP/2: requests that may share a connection do, media never does, and an
//! upstream without HTTP/2 still works.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use tokio::task::JoinSet;

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world_with(origin_h2: bool, site_toml: &str) -> World {
    let ca = Ca::new("piano e2e");
    let leaf = ca.leaf(&[ORIGIN_HOST]);
    let origin = if origin_h2 {
        Origin::start(&leaf).await
    } else {
        Origin::start_h1_only(&leaf).await
    };
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        site_toml,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World { ca, origin, relay }
}

impl World {
    fn url(&self, path: &str) -> String {
        format!("https://{SITE_HOST}:{}{path}", self.relay.addr.port())
    }

    async fn get(&self, path: &str) -> (u16, String) {
        let res = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, Proto::H1)
            .get(self.url(path))
            .send()
            .await
            .unwrap();
        (res.status().as_u16(), res.text().await.unwrap())
    }

    /// Sends GETs for all `paths` at once, each on its own client connection.
    async fn get_all(&self, paths: Vec<String>) -> Vec<(u16, String)> {
        let mut set = JoinSet::new();
        for path in paths {
            let req = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, Proto::H1)
                .get(self.url(&path));
            set.spawn(async move {
                let res = req.send().await.unwrap();
                (res.status().as_u16(), res.text().await.unwrap())
            });
        }
        set.join_all().await
    }

    fn last_protos(&self) -> Vec<String> {
        let line = &self.relay.access_lines(ACCESS_LOG, 1)[0];
        line["up"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["proto"].as_str().unwrap_or("-").to_owned())
            .collect()
    }
}

#[tokio::test]
async fn concurrent_api_requests_share_one_upstream_connection() {
    let w = world_with(true, "").await;
    let paths = (0..20).map(|i| format!("/__echo/{i}")).collect();
    for (status, body) in w.get_all(paths).await {
        assert_eq!(status, 200);
        assert!(body.contains("HTTP/2.0"), "{body}");
    }
    assert_eq!(w.origin.connections(), (0, 1));
    assert_eq!(w.last_protos(), ["h2"]);
}

#[tokio::test]
async fn concurrent_image_fetches_share_one_upstream_connection() {
    let w = world_with(true, "").await;
    let paths = (0..20)
        .map(|i| format!("/Items/h2img{i}/Images/Primary"))
        .collect();
    for (status, body) in w.get_all(paths).await {
        assert_eq!(status, 200);
        assert!(body.starts_with("image h2img"), "{body}");
    }
    assert_eq!(w.origin.connections(), (0, 1));
    assert_eq!(w.last_protos(), ["h2"]);
}

#[tokio::test]
async fn path_bytes_survive_http2() {
    let w = world_with(true, "").await;
    let (status, body) = w.get("/__echo/%E6%97%A5%20x?q=a%20b&r=%2F").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("/__echo/%E6%97%A5%20x?q=a%20b&r=%2F"),
        "{body}"
    );
    assert!(body.contains("HTTP/2.0"), "{body}");
}

#[tokio::test]
async fn upstream_without_http2_gets_http1() {
    let w = world_with(false, "").await;
    let paths = (0..5).map(|i| format!("/__echo/{i}")).collect();
    for (status, body) in w.get_all(paths).await {
        assert_eq!(status, 200);
        assert!(body.contains("HTTP/1.1"), "{body}");
    }
    let (status, body) = w.get("/Items/h1img/Images/Primary").await;
    assert_eq!((status, body.as_str()), (200, "image h1img"));
    assert_eq!(w.last_protos(), ["h1"]);
    assert_eq!(w.origin.connections().1, 0);
}

#[tokio::test]
async fn a_site_can_turn_http2_off() {
    let w = world_with(true, "h2 = false").await;
    let (status, body) = w.get("/__echo/off").await;
    assert_eq!(status, 200);
    assert!(body.contains("HTTP/1.1"), "{body}");
    let (status, _) = w.get("/Items/offimg/Images/Primary").await;
    assert_eq!(status, 200);
    assert_eq!(w.origin.connections().1, 0);
}

#[tokio::test]
async fn media_uses_http1() {
    let w = world_with(true, "").await;
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .get(w.url("/videos/h2m/stream?len=5000"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.bytes().await.unwrap().len(), 5000);
    assert_eq!(w.last_protos(), ["h1"]);
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .head(w.url("/videos/h2m/stream?len=5000"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(w.origin.connections().1, 0);
}
