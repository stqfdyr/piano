//! `piano doctor` against a relay running in this process.

use piano::doctor::{Check, Input, Installed, Level, Report, run};
use piano_ctl::proto::Status;
use piano_e2e::origin::Origin;
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use piano_upstream::Resolver;
use std::net::IpAddr;
use std::time::Duration;

async fn doctor(relay: &Relay, status: Option<&Status>, installed: Option<&str>) -> Report {
    let input = Input {
        config: &relay.config_path(),
        status,
        socket: Some(&relay.control_socket()),
        user: "nobody",
        installed: installed
            .map(|sha256| Installed {
                path: "/usr/local/bin/piano".into(),
                sha256: Ok(sha256.to_owned()),
                started_from: true,
            })
            .into_iter()
            .collect(),
        resolver: Resolver::system().with_override(ORIGIN_HOST, &[IpAddr::from([127, 0, 0, 1])]),
    };
    tokio::time::timeout(Duration::from_secs(60), run(&input))
        .await
        .expect("doctor did not end within 60s")
}

fn status(relay: &Relay) -> Status {
    let value = piano_ctl::call(&relay.control_socket(), "status", Duration::from_secs(5)).unwrap();
    serde_json::from_value(value).unwrap()
}

fn find<'a>(r: &'a Report, group: &str, what: &str) -> &'a Check {
    r.checks
        .iter()
        .find(|c| c.group == group && c.what.contains(what))
        .unwrap_or_else(|| panic!("no {group} check for {what}: {r:#?}"))
}

#[tokio::test]
async fn a_healthy_relay_and_what_changes_after_it_loaded() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let leaf = ca.leaf(&[SITE_HOST]);
    let mut setup = RelaySetup::new(&leaf, &roots, origin.addr.port());
    setup.control = true;
    setup.site_toml = "follow = [\"*.cdn.example.net\"]\n";
    let relay = Relay::start(&setup);
    let s = status(&relay);
    let running = s.process.binary_sha256.clone();

    let r = doctor(&relay, Some(&s), running.as_deref()).await;
    // Only the wildcard is not checked.
    assert_eq!(r.worst(), Level::Skip, "{r:#?}");
    assert!(
        r.checks
            .iter()
            .any(|c| c.group == "configuration" && c.detail.contains("covers every site")),
        "{r:#?}"
    );
    assert!(
        find(&r, "access", "reads")
            .what
            .contains(&format!("pid {})", s.pid))
    );
    assert_eq!(
        find(&r, "listening", "127.0.0.1").detail,
        format!("served by pid {}", s.pid)
    );
    assert!(!r.config_failed());
    let up = find(&r, "upstreams", ORIGIN_HOST);
    assert_eq!(up.level, Level::Ok);
    assert!(up.detail.starts_with("127.0.0.1 in "), "{}", up.detail);
    // A wildcard is listed as not checked.
    assert_eq!(
        find(&r, "upstreams", "*.cdn.example.net").level,
        Level::Skip
    );

    // The file changes after loading, and another binary is installed.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    relay.write_config(&setup);
    let r = doctor(&relay, Some(&s), Some("0".repeat(64).as_str())).await;
    assert_eq!(r.worst(), Level::Warn, "{r:#?}");
    let changed = find(&r, "daemon", ".toml");
    assert!(changed.detail.contains("piano reload"), "{changed:?}");
    assert_eq!(
        find(&r, "daemon", "binary").detail,
        "/usr/local/bin/piano is not the binary running; piano upgrade switches to it \
         without dropping streams"
    );
}

#[tokio::test]
async fn a_held_port_and_an_unreachable_alias_are_errors() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let leaf = ca.leaf(&[SITE_HOST]);
    let mut setup = RelaySetup::new(&leaf, &roots, origin.addr.port());
    setup.site_toml = "aliases = [\"missing.invalid\"]\n";
    let relay = Relay::start(&setup);

    // As if the daemon were not running: the relay holding the port is someone else.
    let r = doctor(&relay, None, None).await;
    assert_eq!(find(&r, "daemon", "not running").level, Level::Warn);
    let port = find(&r, "listening", "127.0.0.1");
    assert_eq!(port.level, Level::Error, "{port:?}");
    assert!(
        port.detail
            .contains(&format!("(pid {})", std::process::id())),
        "{port:?}"
    );
    let alias = find(&r, "upstreams", "missing.invalid");
    assert_eq!(alias.level, Level::Error, "{alias:?}");
    assert_eq!(find(&r, "upstreams", ORIGIN_HOST).level, Level::Ok);
}

#[tokio::test]
async fn a_broken_configuration_is_the_only_check() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup::new(
        &ca.leaf(&[SITE_HOST]),
        &roots,
        origin.addr.port(),
    ));
    relay.write_config_text("listen = \n");
    let r = doctor(&relay, None, None).await;
    assert_eq!(r.checks.len(), 1, "{r:#?}");
    assert_eq!(r.checks[0].level, Level::Error);
    assert!(r.config_failed());
}
