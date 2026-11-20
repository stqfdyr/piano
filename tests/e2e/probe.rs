//! `piano probe` through the relay and directly to the origin.

use piano::probe::{Args, Credentials, Report, run};
use piano_e2e::origin::{BLOCKED_UA, Origin, PROBE_MEDIA_LEN, PROBE_PASSWORD, PROBE_USER};
use piano_e2e::pki::Ca;
use piano_e2e::relay::{Relay, RelaySetup};
use piano_e2e::{ORIGIN_HOST, SITE_HOST};
use piano_upstream::Resolver;
use std::net::IpAddr;
use std::time::Duration;

/// Rewrites the User-Agent the fake origin refuses, as a site's rules would.
const SITE_TOML: &str = r#"[[site.ua]]
match = "^Blocked/"
set = "EmbyMini/0.1.0"
"#;

async fn probe(relay: &Relay, args: &Args) -> Report {
    let resolver = Resolver::system().with_override(ORIGIN_HOST, &[IpAddr::from([127, 0, 0, 1])]);
    tokio::time::timeout(
        Duration::from_secs(60),
        run(&relay.config(), &resolver, args),
    )
    .await
    .expect("probe did not end within 60s")
    .unwrap()
}

fn args(login: Option<&str>, direct: bool, agents: &[&str]) -> Args {
    Args {
        site: SITE_HOST.to_owned(),
        login: login.map(|password| Credentials {
            user: PROBE_USER.to_owned(),
            password: password.to_owned(),
        }),
        direct,
        user_agents: agents.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn names(r: &Report) -> Vec<&str> {
    r.steps.iter().map(|s| s.name).collect()
}

#[tokio::test]
async fn walks_the_site_through_the_relay() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let leaf = ca.leaf(&[SITE_HOST]);
    let mut setup = RelaySetup::new(&leaf, &roots, origin.addr.port());
    setup.site_toml = SITE_TOML;
    let relay = Relay::start(&setup);

    let r = probe(&relay, &args(Some(PROBE_PASSWORD), false, &[])).await;
    assert!(r.ok(), "{r:#?}");
    assert_eq!(r.via, "relay");
    assert_eq!(r.address, relay.addr.to_string());
    assert_eq!(
        names(&r),
        [
            "login", "public", "views", "latest", "image", "playback", "media"
        ]
    );
    let note = |name: &str| &r.steps.iter().find(|s| s.name == name).unwrap().note;
    let port = relay.addr.port();
    assert!(
        note("public").contains(&format!("LocalAddress {SITE_HOST}:{port}")),
        "{}",
        note("public")
    );
    assert_eq!(note("views"), "2 libraries");
    assert_eq!(note("playback"), "direct stream: relative");
    assert_eq!(note("media"), &format!("of {PROBE_MEDIA_LEN} bytes"));
    let media = r.steps.iter().find(|s| s.name == "media").unwrap();
    assert_eq!((media.status, media.bytes), (Some(206), 1 << 20));
    // The site's rule turns the refused User-Agent into an accepted one.
    let r = probe(&relay, &args(Some(PROBE_PASSWORD), false, &["Blocked/1.0"])).await;
    assert!(r.ok(), "{r:#?}");
    let text = serde_json::to_string(&r).unwrap();
    assert!(
        !text.contains("probe-token") && !text.contains(PROBE_USER),
        "{text}"
    );
}

#[tokio::test]
async fn a_refused_login_stops_after_the_public_step() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let relay = Relay::start(&RelaySetup::new(
        &ca.leaf(&[SITE_HOST]),
        &roots,
        origin.addr.port(),
    ));
    let r = probe(&relay, &args(Some("wrong"), false, &[])).await;
    assert!(!r.ok());
    assert_eq!(names(&r), ["login", "public"]);
    assert_eq!(r.steps[0].status, Some(401));
    assert!(r.steps[1].ok, "{r:#?}");
}

#[tokio::test]
async fn direct_shows_what_the_upstream_does_with_each_user_agent() {
    let ca = Ca::new("piano e2e");
    let origin = Origin::start(&ca.leaf(&[ORIGIN_HOST])).await;
    let roots = [ca.cert_pem()];
    let leaf = ca.leaf(&[SITE_HOST]);
    let mut setup = RelaySetup::new(&leaf, &roots, origin.addr.port());
    setup.site_toml = SITE_TOML;
    let relay = Relay::start(&setup);
    let blocked = format!("{BLOCKED_UA}1.0");
    let r = probe(
        &relay,
        &args(Some(PROBE_PASSWORD), true, &["Fine/1.0", &blocked]),
    )
    .await;
    assert_eq!(r.via, "direct");
    assert_eq!(r.server_name, ORIGIN_HOST);
    assert_eq!(r.address, origin.addr.to_string());
    let of = |ua: &str| -> Vec<(&str, bool)> {
        r.steps
            .iter()
            .filter(|s| s.user_agent == ua && s.name != "login")
            .map(|s| (s.name, s.ok))
            .collect()
    };
    assert!(of("Fine/1.0").iter().all(|(_, ok)| *ok), "{r:#?}");
    let refused = of(&blocked);
    assert_eq!(refused[0], ("public", true));
    assert_eq!(refused[1], ("views", false));
    let views = r
        .steps
        .iter()
        .find(|s| s.user_agent == blocked && s.name == "views")
        .unwrap();
    assert_eq!(views.status, Some(403));
    assert_eq!(views.note, "API policy denied");
}
