//! Bytes per site and kind: counted for status, and written to the traffic record.

use piano_ctl::proto::Status;
use piano_e2e::client::{Proto, client};
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use std::time::{Duration, Instant};

async fn get(ca: &Ca, relay: &Relay, proto: Proto, path: &str) -> usize {
    let res = client(ca.cert_der(), SITE_HOST, relay.addr, proto)
        .get(format!("https://{SITE_HOST}:{}{path}", relay.addr.port()))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{path}: {}", res.status());
    res.bytes().await.unwrap().len()
}

async fn status_after(relay: &Relay, n: u64) -> Status {
    let socket = relay.control_socket();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = socket.clone();
        let v = tokio::task::spawn_blocking(move || {
            piano_ctl::call(&s, "status", Duration::from_secs(10))
        })
        .await
        .unwrap()
        .unwrap();
        let status: Status = serde_json::from_value(v).unwrap();
        if status.sites[0].traffic.total.requests >= n {
            return status;
        }
        assert!(Instant::now() < deadline, "{status:#?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn bytes_are_counted_by_kind_and_recorded_per_day() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        control: true,
        ..RelaySetup::new(&ca.leaf(&[SITE_HOST]), &roots, origin.addr.port())
    });

    // Media through the media engine, an image fetched once and then served from
    // memory, and an API body through the relay.
    let media = get(&ca, &relay, Proto::H1, "/videos/t1/stream.mkv?len=300000").await;
    assert_eq!(media, 300_000);
    for _ in 0..2 {
        assert_eq!(
            get(&ca, &relay, Proto::H2, "/Items/a1/Images/Primary").await,
            8
        );
    }
    assert_eq!(get(&ca, &relay, Proto::H2, "/__bytes/50000").await, 50_000);

    let s = status_after(&relay, 4).await;
    let total = &s.sites[0].traffic.total;
    assert_eq!(total.bytes_sent, 300_000 + 16 + 50_000);
    assert_eq!(total.bytes_fetched, 300_000 + 8 + 50_000);
    assert_eq!(s.sites[0].traffic.recent.bytes_sent, total.bytes_sent);

    let record = relay.traffic();
    assert_eq!(record.schema, 1);
    assert_eq!(record.days.len(), 1, "{record:?}");
    let today = record.days.values().next().unwrap();
    let site = today["media"];
    assert_eq!(
        (
            site.sent.media,
            site.sent.image,
            site.sent.other,
            site.sent.socket
        ),
        (300_000, 16, 50_000, 0)
    );
    assert_eq!(
        (site.fetched.media, site.fetched.image, site.fetched.other),
        (300_000, 8, 50_000)
    );

    // Only what was added since the last write goes in.
    assert_eq!(get(&ca, &relay, Proto::H1, "/__bytes/1000").await, 1000);
    status_after(&relay, 5).await;
    let record = relay.traffic();
    let site = record.days.values().next().unwrap()["media"];
    assert_eq!(site.sent.other, 51_000);
    assert_eq!(site.fetched.other, 51_000);
}
