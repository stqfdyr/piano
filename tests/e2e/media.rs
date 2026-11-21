//! Media streams: a stalled or broken upstream body continues from another request.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::{Origin, pattern_byte};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{ACCESS_LOG, Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
}

async fn world() -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup::new(
        &ca.leaf(&[SITE_HOST]),
        &roots,
        origin.addr.port(),
    ));
    World { ca, origin, relay }
}

struct Got {
    status: u16,
    content_range: Option<String>,
    /// The body, or the error that cut it short.
    body: Result<Vec<u8>, String>,
    took: Duration,
}

impl World {
    async fn get(&self, proto: Proto, path: &str, range: Option<&str>) -> Got {
        let url = format!("https://{SITE_HOST}:{}{path}", self.relay.addr.port());
        let mut req = client(self.ca.cert_der(), SITE_HOST, self.relay.addr, proto).get(url);
        if let Some(r) = range {
            req = req.header("range", r);
        }
        let started = Instant::now();
        let res = req.send().await.unwrap();
        let status = res.status().as_u16();
        let content_range = res
            .headers()
            .get("content-range")
            .map(|v| v.to_str().unwrap().to_owned());
        let body = res
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("{e:?}"));
        Got {
            status,
            content_range,
            body,
            took: started.elapsed(),
        }
    }
}

/// Whether `body` is the pattern from file offset `start`.
fn is_pattern(body: &[u8], start: u64) -> bool {
    body.iter()
        .enumerate()
        .all(|(i, &b)| b == pattern_byte(start + i as u64))
}

fn ranges(seen: &[Option<String>]) -> Vec<&str> {
    seen.iter().map(|r| r.as_deref().unwrap_or("-")).collect()
}

const LEN: u64 = 300_000;

#[tokio::test]
async fn a_stalled_body_gets_a_second_request() {
    let w = world().await;
    for proto in [Proto::H1, Proto::H2] {
        let key = format!("hedge-{proto:?}");
        let path = format!("/videos/{key}/stream.mkv?len={LEN}&plan=b20000,-");
        let got = w.get(proto, &path, Some("bytes=1000-")).await;
        assert_eq!(got.status, 206);
        assert_eq!(
            got.content_range.as_deref(),
            Some("bytes 1000-299999/300000")
        );
        let body = got.body.unwrap();
        assert_eq!(body.len() as u64, LEN - 1000);
        assert!(is_pattern(&body, 1000));
        assert!(got.took < Duration::from_secs(8), "{:?}", got.took);
        assert_eq!(
            ranges(&w.origin.seen(&key)),
            ["bytes=1000-", "bytes=1000-299999"]
        );
    }
    let lines = w.relay.access_lines(ACCESS_LOG, 2);
    let up = lines[0]["up"].as_array().unwrap();
    let srcs: Vec<u64> = up.iter().map(|a| a["src"].as_u64().unwrap()).collect();
    assert_eq!(srcs, [0, 1]);
    assert_eq!(lines[0]["end"], "ok");
    assert_eq!(lines[0]["bytes_out"], LEN - 1000);
}

#[tokio::test]
async fn a_broken_body_resumes_where_it_stopped() {
    let w = world().await;
    let path = format!("/videos/cut/stream.mkv?len={LEN}&plan=c100000,-");
    let got = w.get(Proto::H1, &path, None).await;
    assert_eq!(got.status, 200);
    let body = got.body.unwrap();
    assert_eq!(body.len() as u64, LEN);
    assert!(is_pattern(&body, 0));
    assert!(got.took < Duration::from_secs(2), "{:?}", got.took);
    let seen = w.origin.seen("cut");
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0], None);
    let resumed = seen[1].as_deref().unwrap();
    let from: u64 = resumed
        .strip_prefix("bytes=")
        .and_then(|r| r.strip_suffix("-299999"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(from <= 100_000, "{resumed}");
}

#[tokio::test]
async fn a_pause_mid_body_gets_a_second_request() {
    let w = world().await;
    let path = format!("/videos/pause/stream.mkv?len={LEN}&plan=s131072:20000,-");
    let got = w.get(Proto::H2, &path, Some("bytes=0-")).await;
    assert_eq!(got.status, 206);
    let body = got.body.unwrap();
    assert_eq!(body.len() as u64, LEN);
    assert!(is_pattern(&body, 0));
    assert!(got.took < Duration::from_secs(8), "{:?}", got.took);
    assert_eq!(
        ranges(&w.origin.seen("pause")),
        ["bytes=0-", "bytes=131072-299999"]
    );
}

#[tokio::test]
async fn a_resume_walks_the_redirect_chain_again() {
    let w = world().await;
    let path = format!("/videos/chain/original.mkv?redirect=1&len={LEN}&plan=c100000,-");
    let got = w.get(Proto::H1, &path, Some("bytes=0-")).await;
    assert_eq!(got.status, 206);
    let body = got.body.unwrap();
    assert!(is_pattern(&body, 0) && body.len() as u64 == LEN);
    assert_eq!(w.origin.redirects("chain"), 2);
    assert_eq!(w.origin.seen("chain").len(), 2);
    let lines = w.relay.access_lines(ACCESS_LOG, 1);
    let statuses: Vec<(u64, u64)> = lines[0]["up"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["src"].as_u64().unwrap(), a["status"].as_u64().unwrap()))
        .collect();
    assert_eq!(statuses, [(0, 302), (0, 206), (1, 302), (1, 206)]);
}

#[tokio::test]
async fn a_changed_file_is_not_spliced_together() {
    let w = world().await;
    let path = format!("/videos/changed/stream.mkv?len={LEN}&plan=c100000,ev2");
    let got = w.get(Proto::H1, &path, Some("bytes=0-")).await;
    assert_eq!(got.status, 206);
    assert!(got.body.is_err(), "the body must break off");
    // The representation changed: no further request can continue the body.
    assert_eq!(w.origin.seen("changed").len(), 2);
    let lines = w.relay.access_lines(ACCESS_LOG, 1);
    assert_eq!(lines[0]["end"], "upstream_error");
    assert!(lines[0]["bytes_out"].as_u64().unwrap() <= 100_000);
}

#[tokio::test]
async fn a_body_without_offsets_is_not_resumed() {
    let w = world().await;
    let path = format!("/videos/live/stream.mkv?len={LEN}&plan=u.c100000");
    let got = w.get(Proto::H1, &path, None).await;
    assert_eq!(got.status, 200);
    assert!(got.body.is_err(), "the body must break off");
    assert_eq!(w.origin.seen("live").len(), 1);
}

#[tokio::test]
async fn at_most_two_requests_wait_for_the_same_bytes() {
    // A read timeout past the second hedge time (6 s), so a third request would be seen.
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        read_timeout: Duration::from_secs(15),
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    let w = World { ca, origin, relay };
    let path = format!("/videos/stuck/stream.mkv?len={LEN}&plan=b30000");
    let url = format!("https://{SITE_HOST}:{}{path}", w.relay.addr.port());
    // HTTP/2 sends the head at once; HTTP/1.1 holds it until the first body bytes.
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H2)
        .get(url)
        .header("range", "bytes=0-")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 206);
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(w.origin.seen("stuck").len(), 2);
}

#[tokio::test]
async fn upstream_errors_reach_the_client() {
    let w = world().await;
    let path = format!("/videos/err/stream.mkv?len={LEN}");
    let got = w.get(Proto::H1, &path, Some("bytes=999999-")).await;
    assert_eq!(got.status, 416);
    assert_eq!(got.content_range.as_deref(), Some("bytes */300000"));
    assert_eq!(got.body.unwrap(), b"");
    assert_eq!(w.origin.seen("err").len(), 1);
}

async fn media_streams(socket: PathBuf) -> u64 {
    let value = tokio::task::spawn_blocking(move || {
        piano_ctl::call(&socket, "status", Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    let status: piano_ctl::proto::Status = serde_json::from_value(value).unwrap();
    status.connections.media_streams
}

/// Polls the relay until it has `n` media streams.
async fn wait_streams(relay: &Relay, n: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let now = media_streams(relay.control_socket()).await;
        if now == n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{now} media streams, expected {n}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_client_that_leaves_ends_its_stream() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        control: true,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    for proto in [Proto::H1, Proto::H2] {
        let url = format!(
            "https://{SITE_HOST}:{}/videos/leave-{proto:?}/stream.mkv?plan=b30000",
            relay.addr.port()
        );
        let req = client(ca.cert_der(), SITE_HOST, relay.addr, proto)
            .get(url)
            .header("range", "bytes=0-")
            .send();
        let task = tokio::spawn(async move { req.await.unwrap().bytes().await });
        wait_streams(&relay, 1).await;
        task.abort();
        wait_streams(&relay, 0).await;
    }
    let lines = relay.access_lines(ACCESS_LOG, 2);
    assert!(
        lines.iter().all(|l| l["end"] == "client_closed"),
        "{lines:?}"
    );
}

#[tokio::test]
async fn a_client_that_stops_reading_keeps_its_stream() {
    // The client stops reading for longer than the upstream read timeout (5 s): a
    // player that is paused must not lose its stream to a stall that is its own.
    const BIG: u64 = 16 << 20;
    let w = world().await;
    for proto in [Proto::H1, Proto::H2] {
        let key = format!("hold-{proto:?}");
        let url = format!(
            "https://{SITE_HOST}:{}/videos/{key}/stream.mkv?len={BIG}",
            w.relay.addr.port()
        );
        let got = tokio::time::timeout(Duration::from_secs(40), async {
            let mut res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, proto)
                .get(url)
                .header("range", "bytes=0-")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 206);
            let mut body = Vec::new();
            while body.len() < 1 << 20 {
                body.extend_from_slice(&res.chunk().await.unwrap().unwrap());
            }
            tokio::time::sleep(Duration::from_secs(7)).await;
            while let Some(c) = res.chunk().await.unwrap() {
                body.extend_from_slice(&c);
            }
            body
        })
        .await
        .expect("stream did not finish");
        assert_eq!(got.len() as u64, BIG, "{proto:?}");
        assert!(is_pattern(&got, 0), "{proto:?}");
        assert_eq!(w.origin.seen(&key).len(), 1, "{proto:?}");
    }
}

#[tokio::test]
async fn a_finished_stream_returns_its_connection() {
    let w = world().await;
    for _ in 0..2 {
        let got = w
            .get(
                Proto::H1,
                &format!("/videos/pool/stream.mkv?len={LEN}"),
                Some("bytes=0-"),
            )
            .await;
        assert_eq!(got.body.unwrap().len() as u64, LEN);
    }
    assert_eq!(w.origin.connections(), (1, 0));
}

#[tokio::test]
async fn the_request_that_loses_is_closed() {
    let w = world().await;
    // The first request's body comes after 30 s; the second request wins.
    let path = format!("/videos/lose/stream.mkv?len={LEN}&plan=b30000,-");
    let got = w.get(Proto::H1, &path, Some("bytes=0-")).await;
    assert!(is_pattern(&got.body.unwrap(), 0));
    assert_eq!(w.origin.seen("lose").len(), 2);
    // The winner's connection is pooled; the loser's is closed at once, well before its
    // own read timeout (5 s from its head) would end it.
    let deadline = Instant::now() + Duration::from_millis(500);
    while w.origin.open_connections() > 1 {
        assert!(
            Instant::now() < deadline,
            "the losing request is still open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_stream_whose_requests_keep_failing_gives_up() {
    let w = world().await;
    // After the first request breaks, every request breaks before its first byte.
    let path = format!("/videos/flaky/stream.mkv?len={LEN}&plan=c100000,c0");
    let got = w.get(Proto::H1, &path, Some("bytes=0-")).await;
    assert!(got.body.is_err(), "the body must break off");
    // The first request, then four without progress.
    assert_eq!(w.origin.seen("flaky").len(), 5);
}

#[tokio::test]
async fn a_resume_does_not_carry_the_clients_if_range() {
    let w = world().await;
    // The client's If-Range does not match, so the first response is the whole file;
    // it breaks, and the resume must still get the rest as a range.
    let url = format!(
        "https://{SITE_HOST}:{}/videos/ifr/stream.mkv?len={LEN}&plan=c100000,-",
        w.relay.addr.port()
    );
    let res = client(w.ca.cert_der(), SITE_HOST, w.relay.addr, Proto::H1)
        .get(url)
        .header("range", "bytes=0-")
        .header("if-range", "\"stale\"")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.bytes().await.unwrap();
    assert_eq!(body.len() as u64, LEN);
    assert!(is_pattern(&body, 0));
    assert_eq!(w.origin.seen("ifr").len(), 2);
}
