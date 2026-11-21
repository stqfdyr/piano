//! Access control and reloading.

use piano_e2e::client::{Proto, client};
use piano_e2e::origin::{INFO_PUBLIC, Origin};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};

const OTHER_HOST: &str = "other.example.com";

async fn get(ca: &Ca, relay: &Relay, host: &str) -> reqwest::Result<reqwest::Response> {
    client(ca.cert_der(), host, relay.addr, Proto::H1)
        .get(format!("https://{host}:{}/__info", relay.addr.port()))
        .send()
        .await
}

#[tokio::test]
async fn refused_addresses_are_closed_before_the_handshake() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let relay = Relay::start(&RelaySetup {
        site: &ca.leaf(&[SITE_HOST]),
        extra_roots: &[ca.cert_pem()],
        origin_port: origin.addr.port(),
        allow: &["192.0.2.1", "2001:db8::/32"],
        hosts: &[SITE_HOST],
        block: &[],
        site_toml: "",
        names: &[],
        origin_ips: &[],
        access_log: piano_e2e::relay::ACCESS_LOG,
        limits: "",
        read_timeout: std::time::Duration::from_secs(5),
        control: false,
    });
    let err = get(&ca, &relay, SITE_HOST).await.unwrap_err();
    assert!(err.is_connect(), "{err:?}");
    assert!(relay.denied_connections() >= 1);
    assert_eq!(origin.requests(), 0);
}

#[tokio::test]
async fn reload_replaces_access_certificates_and_sites() {
    let old_ca = Ca::new("piano e2e old");
    let new_ca = Ca::new("piano e2e new");
    let origin = Origin::start(&old_ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [old_ca.cert_pem()];
    let relay = Relay::start(&RelaySetup {
        site: &old_ca.leaf(&[SITE_HOST]),
        extra_roots: &roots,
        origin_port: origin.addr.port(),
        allow: &["192.0.2.1"],
        hosts: &[SITE_HOST],
        block: &[],
        site_toml: "",
        names: &[],
        origin_ips: &[],
        access_log: piano_e2e::relay::ACCESS_LOG,
        limits: "",
        read_timeout: std::time::Duration::from_secs(5),
        control: false,
    });
    assert!(get(&old_ca, &relay, SITE_HOST).await.is_err());

    let restart = relay
        .reload(&RelaySetup {
            site: &new_ca.leaf(&[SITE_HOST, OTHER_HOST]),
            extra_roots: &roots,
            origin_port: origin.addr.port(),
            allow: &["127.0.0.0/8"],
            hosts: &[SITE_HOST, OTHER_HOST],
            block: &[],
            site_toml: "",
            names: &[],
            origin_ips: &[],
            access_log: piano_e2e::relay::ACCESS_LOG,
            limits: "",
            read_timeout: std::time::Duration::from_secs(5),
            control: false,
        })
        .unwrap();
    assert!(restart.is_empty(), "{restart:?}");

    for host in [SITE_HOST, OTHER_HOST] {
        let res = get(&new_ca, &relay, host).await.unwrap();
        assert_eq!(res.status(), 200, "{host}");
        assert_eq!(res.text().await.unwrap(), INFO_PUBLIC);
    }
    // The old certificate is gone.
    let err = get(&old_ca, &relay, SITE_HOST).await.unwrap_err();
    assert!(err.is_connect(), "{err:?}");
}

#[tokio::test]
async fn failed_reload_keeps_the_running_configuration() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let setup = RelaySetup {
        site: &ca.leaf(&[SITE_HOST]),
        extra_roots: &roots,
        origin_port: origin.addr.port(),
        allow: &["127.0.0.1"],
        hosts: &[SITE_HOST],
        block: &[],
        site_toml: "",
        names: &[],
        origin_ips: &[],
        access_log: piano_e2e::relay::ACCESS_LOG,
        limits: "",
        read_timeout: std::time::Duration::from_secs(5),
        control: false,
    };
    let relay = Relay::start(&setup);

    // The certificate does not cover the added host.
    let err = relay
        .reload(&RelaySetup {
            allow: &["192.0.2.1"],
            hosts: &[SITE_HOST, OTHER_HOST],
            ..setup
        })
        .unwrap_err();
    assert!(err.to_string().contains(OTHER_HOST), "{err}");
    assert_eq!(get(&ca, &relay, SITE_HOST).await.unwrap().status(), 200);

    // Settings read only at startup are reported, the rest applies.
    let restart = relay
        .reload(&RelaySetup {
            extra_roots: &[],
            ..setup
        })
        .unwrap();
    assert_eq!(restart, ["upstream.extra_roots"]);
    assert_eq!(get(&ca, &relay, SITE_HOST).await.unwrap().status(), 200);
}
