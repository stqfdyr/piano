//! Images: stored bodies, remembered redirects and misses, shared fetches, stale
//! copies, and the upstream request budget.

use piano_ctl::proto::{CacheStats, PurgeReply};
use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::task::Poll;
use std::time::{Duration, Instant};

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world_with(site_toml: &str, control: bool) -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        site_toml,
        control,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World { ca, origin, relay }
}

async fn world() -> World {
    world_with("", false).await
}

struct Got {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl World {
    async fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Got {
        let url = format!("https://{SITE_HOST}:{}{path}", self.relay.addr.port());
        let mut req = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, Proto::H2).get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let res = req.send().await.unwrap();
        Got {
            status: res.status().as_u16(),
            headers: res.headers().clone(),
            body: res.text().await.unwrap(),
        }
    }

    async fn get(&self, path: &str) -> Got {
        self.get_with(path, &[]).await
    }

    fn cache_fields(&self, n: usize) -> Vec<String> {
        self.relay
            .access_lines(ACCESS_LOG, n)
            .iter()
            .map(|l| l["cache"].as_str().unwrap_or("-").to_owned())
            .collect()
    }
}

#[tokio::test]
async fn images_are_answered_from_memory() {
    let w = world().await;
    let a = w
        .get("/emby/Items/a1/Images/Primary?tag=1&api_key=one")
        .await;
    assert_eq!((a.status, a.body.as_str()), (200, "image a1"));
    assert_eq!(a.headers["content-type"], "image/jpeg");
    // Credentials do not split the cache.
    let b = w
        .get("/emby/Items/a1/Images/Primary?api_key=two&tag=1")
        .await;
    assert_eq!((b.status, b.body.as_str()), (200, "image a1"));
    assert!(b.headers.contains_key("age"));
    assert_eq!(b.headers["etag"], "\"a1\"");
    assert!(b.headers.contains_key("strict-transport-security"));
    // Another tag is another image.
    w.get("/emby/Items/a1/Images/Primary?tag=2").await;
    assert_eq!(w.origin.hits("/emby/Items/a1/Images/Primary"), 2);
    assert_eq!(w.cache_fields(3), ["miss", "hit", "miss"]);
}

#[tokio::test]
async fn a_client_holding_the_image_gets_304() {
    let w = world().await;
    w.get("/Items/c1/Images/Primary").await;
    let again = w
        .get_with("/Items/c1/Images/Primary", &[("if-none-match", "\"c1\"")])
        .await;
    assert_eq!(again.status, 304);
    assert_eq!(again.headers["etag"], "\"c1\"");
    assert_eq!(w.origin.hits("/Items/c1/Images/Primary"), 1);
}

#[tokio::test]
async fn permanent_redirects_are_remembered() {
    // Without stored bodies, every request goes upstream; only the first asks where.
    let w = world_with("[cache]\nimage_memory_mib = 0\n", false).await;
    for _ in 0..3 {
        let got = w.get("/Items/r1/Images/Primary?moved=1").await;
        assert_eq!((got.status, got.body.as_str()), (200, "image r1"));
    }
    assert_eq!(w.origin.hits("/Items/r1/Images/Primary"), 1);
    assert_eq!(w.origin.hits("/img/r1"), 3);
    let lines = w.relay.access_lines(ACCESS_LOG, 3);
    assert_eq!(lines[0]["up"].as_array().unwrap().len(), 2);
    assert_eq!(lines[2]["up"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn missing_images_are_remembered() {
    let w = world().await;
    for _ in 0..3 {
        assert_eq!(w.get("/Items/n1/Images/Logo?codes=404").await.status, 404);
    }
    assert_eq!(w.origin.hits("/Items/n1/Images/Logo"), 1);
    assert_eq!(w.cache_fields(3), ["miss", "missing", "missing"]);
}

#[tokio::test]
async fn concurrent_requests_share_one_fetch() {
    let w = world().await;
    let gets = (0..6).map(|_| w.get("/Items/s1/Images/Primary?delay_ms=300"));
    for got in join_all(gets).await {
        assert_eq!((got.status, got.body.as_str()), (200, "image s1"));
    }
    assert_eq!(w.origin.hits("/Items/s1/Images/Primary"), 1);
    let mut fields = w.cache_fields(6);
    fields.sort();
    assert_eq!(
        fields,
        ["coalesced"; 5]
            .iter()
            .chain(&["miss"])
            .copied()
            .collect::<Vec<_>>()
    );
}

/// Runs `fs` concurrently and returns their outputs in order.
async fn join_all<F: Future>(fs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut fs: Vec<_> = fs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<F::Output>> = fs.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (f, o) in fs.iter_mut().zip(out.iter_mut()) {
            if o.is_none() {
                match f.as_mut().poll(cx) {
                    Poll::Ready(v) => *o = Some(v),
                    Poll::Pending => done = false,
                }
            }
        }
        if done { Poll::Ready(()) } else { Poll::Pending }
    })
    .await;
    out.into_iter().map(Option::unwrap).collect()
}

#[tokio::test]
async fn expired_images_are_revalidated_or_stand_in_for_failures() {
    let w = world().await;
    // Confirmed by the upstream with 304.
    w.get("/Items/v1/Images/Primary?ttl=1").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let got = w.get("/Items/v1/Images/Primary?ttl=1").await;
    assert_eq!((got.status, got.body.as_str()), (200, "image v1"));
    // The upstream fails: the expired copy is served.
    w.get("/Items/f1/Images/Primary?ttl=1&codes=200,503").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let got = w.get("/Items/f1/Images/Primary?ttl=1&codes=200,503").await;
    assert_eq!((got.status, got.body.as_str()), (200, "image f1"));
    assert_eq!(w.origin.hits("/Items/v1/Images/Primary"), 2);
    assert_eq!(w.origin.hits("/Items/f1/Images/Primary"), 2);
    assert_eq!(w.cache_fields(4), ["miss", "revalidated", "miss", "stale"]);
}

#[tokio::test]
async fn an_upstream_429_pauses_image_requests_only() {
    let w = world().await;
    let limited = w.get("/Items/l1/Images/Primary?codes=429&retry=30").await;
    assert_eq!(limited.status, 429);
    // The pause outlasts the longest wait: answered here, without asking the upstream.
    let started = Instant::now();
    let shed = w.get("/Items/l2/Images/Primary").await;
    assert_eq!(shed.status, 429);
    assert!(started.elapsed() < Duration::from_secs(2));
    let after: u64 = shed.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((25..=31).contains(&after), "{after}");
    assert_eq!(w.origin.hits("/Items/l2/Images/Primary"), 0);
    // Browsing still reaches the upstream.
    assert_eq!(w.get("/__info").await.status, 200);
    assert_eq!(w.cache_fields(3), ["miss", "shed", "-"]);
}

#[tokio::test]
async fn a_short_pause_is_waited_out() {
    let w = world().await;
    assert_eq!(
        w.get("/Items/p1/Images/Primary?codes=429&retry=1")
            .await
            .status,
        429
    );
    let started = Instant::now();
    let got = w.get("/Items/p2/Images/Primary").await;
    assert_eq!(got.status, 200);
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn images_queue_for_the_upstream_limit() {
    // Burst 4 with a quarter reserved: three images go at once, then one per 200 ms.
    let w = world_with("upstream_limit = { burst = 4, per_sec = 5 }\n", false).await;
    let started = Instant::now();
    let paths: Vec<String> = (0..8)
        .map(|i| format!("/Items/q{i}/Images/Primary"))
        .collect();
    for got in join_all(paths.iter().map(|p| w.get(p))).await {
        assert_eq!(got.status, 200);
    }
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(900), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
}

#[tokio::test]
async fn cache_stats_and_purge() {
    let w = world_with("", true).await;
    w.get("/Items/k1/Images/Primary?moved=1").await;
    w.get("/Items/k1/Images/Primary?moved=1").await;
    w.get("/Items/k2/Images/Primary?codes=404").await;
    let socket = w.relay.control_socket();
    let ask = |cmd: &'static str| {
        let socket = socket.clone();
        tokio::task::spawn_blocking(move || {
            piano_ctl::call(&socket, cmd, Duration::from_secs(10)).unwrap()
        })
    };
    let s: CacheStats = serde_json::from_value(ask("cache").await.unwrap()).unwrap();
    assert_eq!((s.images, s.missing, s.redirects), (1, 1, 1));
    assert_eq!((s.hits, s.misses), (1, 2));
    assert!(s.bytes > 0);
    assert_eq!(s.upstreams.len(), 1);
    assert_eq!(s.upstreams[0].burst, None);
    let p: PurgeReply = serde_json::from_value(ask("cache purge").await.unwrap()).unwrap();
    assert_eq!((p.images, p.missing, p.redirects), (1, 1, 1));
    let s: CacheStats = serde_json::from_value(ask("cache").await.unwrap()).unwrap();
    assert_eq!((s.images, s.missing, s.redirects, s.bytes), (0, 0, 0, 0));
}
