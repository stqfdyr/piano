//! The control socket: status and reload.

use piano_ctl::proto::{ReloadReply, Status};
use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

async fn ask<T: serde::de::DeserializeOwned>(socket: PathBuf, cmd: &'static str) -> T {
    let value =
        tokio::task::spawn_blocking(move || piano_ctl::call(&socket, cmd, Duration::from_secs(30)))
            .await
            .unwrap()
            .unwrap();
    serde_json::from_value(value).unwrap()
}

/// The status once the first site has counted `n` requests: they are counted just
/// after the response ends, so the client may get there first.
async fn status_after(relay: &Relay, n: u64) -> Status {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s: Status = ask(relay.control_socket(), "status").await;
        if s.sites[0].traffic.total.requests >= n {
            return s;
        }
        assert!(Instant::now() < deadline, "{s:#?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn get(ca: &Ca, relay: &Relay, path: &str) -> u16 {
    client(ca.cert_der(), SITE_HOST, relay.addr, Proto::H2)
        .get(format!("https://{SITE_HOST}:{}{path}", relay.addr.port()))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

struct World {
    ca: Ca,
    origin: Origin,
    relay: Relay,
    roots: Vec<String>,
}

async fn world() -> World {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = vec![ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        control: true,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });
    World {
        ca,
        origin,
        relay,
        roots,
    }
}

#[tokio::test]
async fn status_counts_requests_and_describes_the_daemon() {
    let w = world().await;
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 200);
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 200);
    let s = status_after(&w.relay, 2).await;
    assert_eq!(s.schema, 1);
    assert_eq!(s.pid, std::process::id());
    let site = &s.sites[0];
    assert_eq!(site.name, "media");
    assert_eq!(site.host, SITE_HOST);
    assert_eq!(
        site.upstream,
        format!("{ORIGIN_HOST}:{}", w.origin.addr.port())
    );
    assert_eq!(site.address, w.origin.addr.to_string());
    for c in [&site.traffic.total, &site.traffic.recent] {
        assert_eq!(c.requests, 2);
        assert_eq!(c.status("2xx"), 2);
        assert_eq!(c.end("ok"), 2);
        assert_eq!(c.upstream_attempts, 2);
    }
    // Every class and end is listed, so scripts can rely on the keys.
    assert_eq!(site.traffic.total.status.len(), 6);
    assert_eq!(site.traffic.total.ends.len(), 10);
    assert_eq!(s.certificate.names, [SITE_HOST]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(s.certificate.not_after.unwrap() > i64::try_from(now).unwrap());
    assert_eq!(s.connections.limit, 1024);
    assert!(s.access_log.path.unwrap().ends_with("access.log"));
    assert!(s.process.rss_bytes.unwrap() > 0);
    assert!(s.config.last_reload.is_none());
    assert!(s.findings.is_empty(), "{:#?}", s.findings);
}

#[tokio::test]
async fn refused_redirects_are_reported() {
    let w = world().await;
    let status = get(&w.ca, &w.relay, "/__redirect?to=https://127.0.0.1:1/x").await;
    assert_eq!(status, 502);
    let s = status_after(&w.relay, 1).await;
    let recent = &s.sites[0].traffic.recent;
    assert_eq!(recent.end("redirect_refused"), 1);
    assert_eq!(recent.status("5xx"), 1);
    let codes: Vec<&str> = s.findings.iter().map(|f| f.code.as_str()).collect();
    assert_eq!(codes, ["redirect_refused"]);
}

#[tokio::test]
async fn reload_reports_success_failure_and_settings_that_need_a_restart() {
    let w = world().await;
    let leaf = w.ca.leaf(&[SITE_HOST]);
    let setup = |block, limits| RelaySetup {
        control: true,
        block,
        limits,
        ..RelaySetup::new(&leaf, &w.roots, w.origin.addr.port())
    };
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 200);

    w.relay.write_config(&setup(&["/__info"], ""));
    let r: ReloadReply = ask(w.relay.control_socket(), "reload").await;
    assert!(r.ok, "{r:?}");
    assert!(r.restart_needed.is_empty());
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 404);

    w.relay.write_config_text("[server\n");
    let r: ReloadReply = ask(w.relay.control_socket(), "reload").await;
    assert!(!r.ok);
    assert!(r.config_error);
    assert!(r.error.unwrap().contains("cannot parse"));
    // The running configuration stays.
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 404);
    let s: Status = ask(w.relay.control_socket(), "status").await;
    assert!(!s.config.last_reload.unwrap().ok);
    assert!(s.findings.iter().any(|f| f.code == "reload_failed"));

    w.relay.write_config(&setup(&[], "max_connections = 10"));
    let r: ReloadReply = ask(w.relay.control_socket(), "reload").await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.restart_needed, ["limits.max_connections"]);
    assert_eq!(get(&w.ca, &w.relay, "/__info").await, 200);
    let s: Status = ask(w.relay.control_socket(), "status").await;
    let codes: Vec<&str> = s.findings.iter().map(|f| f.code.as_str()).collect();
    assert_eq!(codes, ["restart_needed"]);
}

#[tokio::test]
async fn the_socket_is_removed_when_the_daemon_stops() {
    let w = world().await;
    let socket = w.relay.control_socket();
    assert!(socket.exists());
    drop(w.relay);
    assert!(!socket.exists());
}
