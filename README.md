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
```

The release binary is built for `x86_64-unknown-linux-musl` with
`target-cpu=x86-64-v2`, so it runs on any x86-64 Linux host from about 2009 onwards.

## Configure

`/etc/piano/piano.toml`:

```toml
[tls]
cert = "/etc/letsencrypt/live/media.example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/media.example.com/privkey.pem"

[[site]]
host     = "media.example.com"
upstream = "https://emby.example.net"
```

- `listen` defaults to `[::]:443`.
- The certificate must cover every site host. Connections without SNI, or for a host
  that is not a site, are refused during the TLS handshake.
- Upstreams must be `https://` with a DNS name; certificate verification is always on.
  Extra trust anchors can be added with `[upstream] extra_roots = ["/path/ca.pem"]`;
  they are added to the system roots, not substituted for them.

## Run

```sh
piano config check     # validate without starting anything
piano run              # run in the foreground (for systemd or OpenRC)
piano version
```

Exit codes: 0 success, 1 runtime error, 2 usage or configuration error.

## License

Apache-2.0. `third_party/pingora` is a trimmed fork of
[Cloudflare Pingora](https://github.com/cloudflare/pingora), also Apache-2.0; see
`third_party/pingora/PATCHES.md` for what was changed.
