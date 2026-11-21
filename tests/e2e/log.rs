//! The access log: one JSON line per request, credentials removed.

use crate::{World, url, world};
use piano_e2e::client::{Proto, client, connect, read_response};
use piano_e2e::origin::INFO_PUBLIC;
use piano_e2e::relay::{ACCESS_LOG, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

fn is_id(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

async fn get(w: &World, proto: Proto, path: &str) -> reqwest::Response {
    client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto)
        .get(url(w, path))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn each_request_is_one_line_without_credentials() {
    let w = world(None, true).await;
    let path = "/__info?api_key=sekrit1&X-Emby-Token=sekrit2&Fields=a";
    let mut n = 0;
    for proto in [Proto::H1, Proto::H2] {
        // Two requests on one connection.
        let c = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto);
        for _ in 0..2 {
            let res = c
                .get(url(&w, path))
                .header("user-agent", "TestPlayer/1.0")
                .header("x-emby-token", "sekrit3")
                .send()
                .await
                .unwrap();
            assert_eq!(res.text().await.unwrap(), INFO_PUBLIC);
        }
        n += 2;
        let lines = w.relay.access_lines(ACCESS_LOG, n);
        let (a, b) = (&lines[n - 2], &lines[n - 1]);
        for l in [a, b] {
            assert!(is_id(&l["rid"]) && is_id(&l["cid"]), "{l}");
            assert_eq!(l["site"], "media", "{l}");
            assert_eq!(l["client"], "127.0.0.1", "{l}");
            let want = if matches!(proto, Proto::H2) {
                "h2"
            } else {
                "h1"
            };
            assert_eq!(l["proto"], want, "{l}");
            assert_eq!(l["method"], "GET", "{l}");
            assert_eq!(
                l["path"], "/__info?api_key=REDACTED&X-Emby-Token=REDACTED&Fields=a",
                "{l}"
            );
            assert_eq!(l["class"], "api", "{l}");
            assert_eq!(l["status"], 200, "{l}");
            assert_eq!(l["bytes_out"], INFO_PUBLIC.len(), "{l}");
            assert!(l["dur_ms"].is_u64() && l["ttfb_ms"].is_u64(), "{l}");
            assert_eq!(l["end"], "ok", "{l}");
            assert!(l["err"].is_null(), "{l}");
            assert_eq!(l["ua"], "TestPlayer/1.0", "{l}");
            assert!(l["range"].is_null() && l["cf_ray"].is_null(), "{l}");
            let up = l["up"].as_array().unwrap();
            assert_eq!(up.len(), 1, "{l}");
            assert_eq!(up[0]["host"], ORIGIN_HOST, "{l}");
            assert_eq!(
                up[0]["addr"],
                format!("127.0.0.1:{}", w.origin.addr.port()),
                "{l}"
            );
            assert_eq!(up[0]["status"], 200, "{l}");
            assert!(
                up[0]["error"].is_null() && up[0]["reused"].is_boolean(),
                "{l}"
            );
        }
        assert_ne!(a["rid"], b["rid"]);
        assert_eq!(a["cid"], b["cid"], "one connection");
        // The second request finds the upstream connection of the first in the pool.
        assert_eq!(b["up"][0]["reused"], true, "{b}");
        assert!(b["up"][0]["connect_ms"].is_null(), "{b}");
    }
    let text = w.relay.access_text(ACCESS_LOG);
    assert!(!text.contains("sekrit"), "{text}");
}

#[tokio::test]
async fn range_and_upstream_ray_are_recorded() {
    let w = world(None, true).await;
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H2)
        .get(url(&w, "/__bytes/1000"))
        .header("range", "bytes=10-19")
        .send()
        .await
        .unwrap();
    assert_eq!(res.bytes().await.unwrap().len(), 10);
    get(&w, Proto::H2, "/__cdn").await;
    let lines = w.relay.access_lines(ACCESS_LOG, 2);
    let l = &lines[0];
    assert_eq!(l["range"], "bytes=10-19", "{l}");
    assert_eq!(l["status"], 206, "{l}");
    assert_eq!(l["bytes_out"], 10, "{l}");
    assert_eq!(lines[1]["cf_ray"], "0123456789abcdef-LAX", "{}", lines[1]);
}

// The client's connection tasks must keep running while the test thread waits for the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_goes_away_is_logged_as_closed() {
    let w = world(None, true).await;
    for (i, proto) in [Proto::H1, Proto::H2].into_iter().enumerate() {
        let mut res = get(&w, proto, "/__bytes/268435456").await;
        assert!(res.chunk().await.unwrap().is_some());
        drop(res);
        let lines = w.relay.access_lines(ACCESS_LOG, i + 1);
        let l = &lines[i];
        assert_eq!(l["end"], "client_closed", "{proto:?}: {l}");
        assert_eq!(l["status"], 200, "{l}");
        assert!(l["bytes_out"].as_u64().unwrap() < 268_435_456, "{l}");
        assert!(l["err"].is_string(), "{l}");
    }
}

#[tokio::test]
async fn local_answers_are_logged() {
    let ca = piano_e2e::pki::Ca::new("piano e2e");
    let origin = piano_e2e::origin::Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = piano_e2e::relay::Relay::start(&RelaySetup {
        block: &["/emby/api/danmu/"],
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    let c = client(ca.cert_der(), SITE_HOST, relay.addr, Proto::H1);
    let base = format!("https://{SITE_HOST}:{}", relay.addr.port());
    for (path, status) in [("/emby/api/danmu/1", 404), ("/__piano/health", 200)] {
        let res = c.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(res.status(), status, "{path}");
    }
    // A host that is not a site, on a connection opened for one.
    let mut io = connect(ca.cert_der(), SITE_HOST, relay.addr, Proto::H1).await;
    io.write_all(b"GET / HTTP/1.1\r\nhost: other.example.com\r\n\r\n")
        .await
        .unwrap();
    io.flush().await.unwrap();
    let (head, _) = read_response(&mut io).await;
    assert!(head.starts_with("HTTP/1.1 421"), "{head}");

    let lines = relay.access_lines(ACCESS_LOG, 3);
    for (l, status) in lines.iter().zip([404, 200, 421]) {
        assert_eq!(l["status"], status, "{l}");
        assert_eq!(l["class"], "local", "{l}");
        assert_eq!(l["end"], "ok", "{l}");
        assert_eq!(l["up"], serde_json::json!([]), "{l}");
        assert!(l["ttfb_ms"].is_null(), "{l}");
    }
    assert!(lines[2]["site"].is_null(), "{}", lines[2]);
    assert_eq!(origin.requests(), 0);
}

#[tokio::test]
async fn logrotate_reopen_and_reload_move_the_file() {
    let ca = piano_e2e::pki::Ca::new("piano e2e");
    let origin = piano_e2e::origin::Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let leaf = ca.leaf(&[SITE_HOST]);
    let relay = piano_e2e::relay::Relay::start(&RelaySetup::new(&leaf, &roots, origin.addr.port()));
    let c = client(ca.cert_der(), SITE_HOST, relay.addr, Proto::H1);
    let base = format!("https://{SITE_HOST}:{}", relay.addr.port());
    let hit = |n: u32| c.get(format!("{base}/__info?n={n}")).send();

    hit(1).await.unwrap();
    relay.access_lines(ACCESS_LOG, 1);
    std::fs::rename(relay.log_path(ACCESS_LOG), relay.log_path("rotated.log")).unwrap();
    relay.reopen_access_log();
    hit(2).await.unwrap();
    assert_eq!(relay.access_lines(ACCESS_LOG, 1)[0]["path"], "/__info?n=2");
    assert_eq!(relay.access_lines("rotated.log", 1).len(), 1);

    relay
        .reload(&RelaySetup {
            access_log: "moved.log",
            ..RelaySetup::new(&leaf, &roots, origin.addr.port())
        })
        .unwrap();
    hit(3).await.unwrap();
    assert_eq!(relay.access_lines("moved.log", 1)[0]["path"], "/__info?n=3");
    assert_eq!(relay.access_lines(ACCESS_LOG, 1).len(), 1);

    relay
        .reload(&RelaySetup {
            access_log: "",
            ..RelaySetup::new(&leaf, &roots, origin.addr.port())
        })
        .unwrap();
    hit(4).await.unwrap();
    hit(5).await.unwrap();
    assert_eq!(relay.access_lines("moved.log", 1).len(), 1);
}
