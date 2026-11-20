# piano

A small, fast TLS relay for Emby servers.

piano sits on a VPS between Emby clients and an Emby server, terminates TLS for a
public host name and relays every request — API calls, images and media streams — to
the upstream server over a verified TLS connection. The upstream address is never
exposed to clients.

Status: early development. The relay core works; most features below are planned.

## Build

Requires Rust 1.100 (pinned in `rust-toolchain.toml`).

```sh
cargo xtask ci     # fmt, clippy, tests, dependency policy (needs cargo-deny)
cargo xtask dist   # static musl binary in target/dist/
cargo xtask deploy HOST [--instance NAME] [--rollback]
                   # build, install on HOST over ssh, piano upgrade, verify
```

The release binary is built for `x86_64-unknown-linux-musl` with
`target-cpu=x86-64-v2`, so it runs on any x86-64 Linux host from about 2009 onwards.

## Configure

`/etc/piano/piano.toml`:

```toml
[tls]
cert = "/etc/letsencrypt/live/media.example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/media.example.com/privkey.pem"

[access]
allow = ["203.0.113.7", "2001:db8:1:2::/64"]

[[site]]
host     = "media.example.com"
upstream = "https://emby.example.net"
```

- `listen` defaults to `[::]:443`.
- `access.allow` lists the client addresses and networks that may connect; anyone else
  is disconnected before the TLS handshake. It must not be empty: to serve every
  address, write `allow = ["0.0.0.0/0", "::/0"]` (`config check` warns about it).
  IPv4 clients of a dual-stack listener match IPv4 entries.
- The certificate must cover every site host. Connections without SNI, or for a host
  that is not a site, are refused during the TLS handshake.
- Upstreams must be `https://` with a DNS name; certificate verification is always on.
  Extra trust anchors can be added with `[upstream] extra_roots = ["/path/ca.pem"]`;
  they are added to the system roots, not substituted for them.

## Run

```sh
piano config check     # validate without starting anything
piano run              # run in the foreground (the service runs this)
piano version
```

Send `SIGHUP` to reload the configuration file: certificates, the allow list and sites
are replaced together, or not at all if the new file has an error (the error is
logged). Requests in progress finish with the configuration they started with.
Changes to `server` settings and `upstream.extra_roots` need a restart.

Exit codes: 0 success, 1 runtime error, 2 usage or configuration error, 3 `config
check` passed with warnings.

## Install as a service

`contrib/` holds a systemd unit, an OpenRC script and a logrotate file;
`contrib/install.sh` installs them with the binary (as root, from a directory with the
binary and the contrib files):

```sh
sh install.sh --binary ./piano-0.1.0-x86_64-linux-musl
```

It creates the `piano` user, installs `/usr/local/bin/piano`, the service and
`/etc/logrotate.d/piano`, and on the first run writes an example
`/etc/piano/piano.toml`. Edit that and run the script again: it checks the
configuration and lets the `piano` group read the certificate and key files named in
it (and enter the directories above them; certbot keeps a key's group when it renews
the key). `--no-cert-access` leaves file permissions alone. The script neither enables
nor restarts the service; it prints what to run next.

The daemon runs as `piano` with only `CAP_NET_BIND_SERVICE`; the systemd unit adds
the usual sandboxing (read-only system, private `/tmp`, a system call filter).

- **Upgrade**: run the script with the new binary, then `piano upgrade` (OpenRC:
  `rc-service piano upgrade`). The new process takes the listening sockets over; the
  old one finishes its media streams, for `server.drain_timeout` at most. The binary
  replaced stays as `/usr/local/bin/piano.prev`: to go back, run the script with
  `--binary /usr/local/bin/piano.prev` and upgrade again.
- **Stop**: `systemctl stop piano` or `rc-service piano stop` run `piano stop`, which
  waits for the daemon and an old process still draining.
- **Reload**: `systemctl reload piano` or `rc-service piano reload`; a configuration
  error is printed and the running configuration stays.
- A second OpenRC instance (for example on another port): `install.sh --instance NAME`
  adds `piano.NAME` reading `/etc/piano/NAME.toml`, which needs its own
  `control.socket`, `log.access` and `traffic.file`.

## Logs

```toml
[log]
access = "/var/log/piano/access.log"   # "" turns the access log off
level  = "info"                        # error | warn | info | debug | trace
```

- **Access log**: one JSON line per request (a websocket when it closes) with the site,
  client, path, status, bytes, timings, how the request ended (`end`: `ok`,
  `client_closed`, `connect_failed`, `redirect_refused`, ...) and every upstream
  attempt (`up`: host, address, pooled or new connection, connect time, status or
  error). Rotate it with logrotate and send `SIGUSR1` in `postrotate` to reopen it.
- **Diagnostic log** on stderr: `<UTC time> <LEVEL> <target>: <message> key=value ...`.
  ERROR needs an operator, WARN is a handled failure (for example a failed request),
  INFO is lifecycle. `--log-level` overrides the configured level.
- Each request carries a `rid` and each connection a `cid`; diagnostic records about a
  request carry the same `rid=`, so the two logs can be joined.
- Credentials are always removed: values of parameters named `api_key`, `apikey` or
  ending in `token` or `authorization` become `REDACTED` in both logs.
- Failed TLS handshakes and connections refused by `access.allow` are reported at
  most once a minute, followed by a count.

## License

Apache-2.0. `third_party/pingora` is a trimmed fork of
[Cloudflare Pingora](https://github.com/cloudflare/pingora), also Apache-2.0; see
`third_party/pingora/PATCHES.md` for what was changed.
