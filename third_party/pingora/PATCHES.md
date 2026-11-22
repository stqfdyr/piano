# Pingora fork

A trimmed copy of [cloudflare/pingora](https://github.com/cloudflare/pingora), used as
path dependencies by the piano workspace. It is its own Cargo workspace (excluded from
the root one) so that the upstream manifests, `workspace = true` inheritance and
formatting settings work unchanged.

- Upstream: `https://github.com/cloudflare/pingora`
- Base commit: `3f87e92c982ee27c714506e16ae362776faea4aa` (2026-11-09, workspace version 0.9.0)
- Upstream checked up to: `3f87e92c982ee27c714506e16ae362776faea4aa` (2026-11-22). The
  weekly `upstream` workflow fails once upstream main moves past it; after looking at the
  new commits (and merging what piano needs), move it to the commit checked.
- License: Apache-2.0, `LICENSE` and the per-crate `LICENSE` files kept as they are.

Format fork code with its own settings (`.rustfmt.toml`, edition 2021): run
`cargo fmt` inside this directory, never `cargo fmt --all` from the root, which would
reformat every file here and bury the patches in noise.

## Tests

The fork's own test suites are not run here; unit tests that read the removed
`pingora-core/tests` fixtures fail. Behaviour piano relies on is covered by piano's
tests; to check a patch against upstream's suite, apply it in an upstream checkout.

## Crates kept

pingora-core, pingora-proxy, pingora-cache (required by pingora-proxy),
pingora-header-serde and pingora-lru (required by pingora-cache), pingora-http,
pingora-http-parser, pingora-error, pingora-timeout, pingora-pool, pingora-runtime,
pingora-rustls.

Further crates from the same base commit may be added when used (tinyufo,
pingora-memory-cache, pingora-limits).

## Patches

Each patch is one commit. When rebasing onto a newer upstream, re-apply them in order
and update the base commit above.

| Id | Patch | Why | Upstream |
|---|---|---|---|
| P0 | Trim: drop crates not kept, all examples and benches, the pingora-proxy integration tests (they need pingora-test-utils) and `pingora-core/tests` (integration tests plus TLS key fixtures, which are not committed here); remove the openssl, boringssl and s2n features and optional dependencies; declare those feature names in `check-cfg` so the untouched `#[cfg(feature = ...)]` code stays warning-free | Only rustls is used; keeps the sources identical to upstream outside the manifests | — |
| P1 | flate2 backend `zlib-ng` → `zlib-rs` (pingora-core) | Pure Rust; removes the cmake build dependency | — |
| P2 | rustls injection points: `TlsSettings::with_server_config(Arc<ServerConfig>)` for listeners, plus `TlsSettings::set_callbacks` so such settings can still carry handshake callbacks; `ConnectorOptions::rustls_client_config` (config + root store) for the upstream connector | The caller needs its own certificate resolver (SNI table, hot reload), ALPN, and extra roots added to (not replacing) the system roots | — |
| P3 | Idle connection memory: box the downstream handshake future (services/listening), the HTTP/2 handshake and accept-loop futures (apps), and `process_request` (pingora-proxy), so a connection waiting for its next request holds only small futures; read the first bytes of an HTTP/1 request into a 256-byte stack buffer before allocating the header buffer (v1 server); give upstream HTTP/1 response header values their own allocation instead of slices of the read buffer (v1 client) | An idle HTTP/1.1 TLS connection held about 47 KiB of heap, mostly future state sized for the whole proxy pipeline; an HTTP/2 downstream's HPACK table kept an entire upstream read buffer alive per connection | — |
| P4 | Downstream handshake failures and timeouts (services/listening) and HTTP/2 handshake failures (apps) are logged at info level under the target `pingora_core::handshake` (`listeners::HANDSHAKE_LOG_TARGET`) instead of at error level; in pingora-proxy, any error that ends reading a request head (the client closed or reset the connection, a read failed or timed out; an invalid head was already at debug) and an error response that cannot be sent before the request is routed are logged at debug level instead of error | Clients cause them at will (scanners, probes for unknown server names, clients that drop a connection halfway through a request): one error record per connection floods the log, and a level filter alone would hide them entirely; a dedicated target lets the application rate limit them | — |
| P5 | Downstream HTTP/1 timeouts (apps, v1 server): `HttpServerOptions::h1_keepalive_timeout` sets the wait for the next request, the first one included, and is restored on every reused connection; `HttpServerOptions::h1_header_read_timeout` limits each read of a request head once its first bytes arrived, closing the connection quietly when it expires | The wait was 60 s before the first request and unlimited after it, since reading a request turns keepalive on without a limit; a client that stopped halfway through a head held the connection for the whole keepalive wait per read | — |
| P6 | Upstream HTTP/2 dial coalescing (connectors/http): while a connection to a peer that may speak HTTP/2 is being set up, further requests for that peer wait for it once and then take a stream on it; peers whose last connection negotiated HTTP/1 are not held back | Without it a burst of concurrent requests to a cold peer opens one connection per request, which is the case HTTP/2 is meant to avoid | — |
| P7 | Drain-aware graceful shutdown (server, pingora-proxy): `Server::set_drained_check` ends the grace period as soon as the given check passes, the grace period becoming an upper bound; upgraded HTTP/1 sessions (websocket) end with `SHUTDOWN_ENDED` once shutdown starts | The grace period slept for its whole length however little work was left, so a restart kept new connections failing for that long; an upgraded session has no end of its own and would always hold the shutdown to its limit | — |
| P8 | Upgrade handoff (server, services/listening): `Server::set_upgrade_handoff` lets the caller decide, once the listening sockets were offered to the new process, whether to stop accepting and shut down or to keep serving, and is told whether sending them worked; listening services report through `watch_listening()` once all their endpoints accept; the two retries while one side waits for the other to start (`No incoming socket transfer`, `server not ready`) log at debug (giving up stays an error) | After sending the sockets the server waited a fixed 5 s and shut down whether or not the new process came up, even when sending them failed, so a failed upgrade stopped the service; every upgrade logged its expected wait as a warning | — |
| P9 | Dependency trim (pingora-core, pingora-rustls): remove YAML configuration loading (`ServerConf::from_yaml` and friends; `Server::new` with a configuration path returns an error), daemonizing and the readiness signal to a daemon parent (`daemon: true` panics), the `derivative` derive (hand-written `Debug` for `PeerOptions`); format the `Date` header with `httpdate` instead of `chrono`; read PEM files with `rustls-pki-types` instead of `rustls-pemfile` and take `rustls-native-certs` 0.8; `tokio-test` becomes a dev-dependency (its `Mock` IO impls compile in tests only) | Drops serde_yaml, unsafe-libyaml, derivative, rustls-pemfile, daemonix and chrono from what pingora pulls in: three unmaintained-crate advisories and ten packages fewer. The binary runs in the foreground under a service manager and builds its `ServerConf` in code | — |
| P10 | `RawTarget` (pingora-http) has a hand-written `Debug` that prints a stored request target as escaped text instead of a list of byte values | pingora logs whole request headers at debug level; a target kept verbatim (absolute-form, non-UTF-8) printed as numbers, which log redaction cannot read, so its query credentials were written to the log | — |
| P11 | The socket a new process receives the listening sockets on during an upgrade (`transfer_fd::get_fds_from`) is created with mode 0600 instead of 0666; the `user` and `group` settings are documented as ignored | 0666 let any local user connect first and hand over descriptors of their own, which the new process then served as its listening sockets while the real ones were lost. The wide mode was for a server that switches users after binding, which the fork no longer does (P9 removed daemonizing); both processes run as the same user | — |
| P12 | Dependency features (pingora-core, pingora-cache, pingora-proxy, pingora-runtime): `regex` without its default features (`std` and `perf` only), the Perl classes of two patterns made ASCII-only: `\w` and `\d` of the HTTP/1 request line repair (`(?-u:…)`, its `.` keeps matching UTF-8 only, so a target with invalid UTF-8 is still refused) and the cache's range parser (`(?-u)`, not used by piano); remove `openssl-probe` (used only by the removed openssl backends), the unused `clap` of pingora-proxy, and the `dial9` features with their optional dependencies; the removed feature names are declared in `check-cfg` | The default features compiled every Unicode table into the binary (about 260 KiB) for classes that only need to match ASCII (method names, digits); an application that needs Unicode classes enables them itself | — |
| P13 | `v1::Connector::keep_idle` (connectors/http) leaves an idle connection to a peer in the pool without sending a request on it: it takes one from the pool and puts it back, or sets up a new one | `release_http_session` pools only connections whose last response was read to the end, so a connection set up ahead of a request could not be pooled. piano replaces a media connection it dropped mid-body with one set up in the background when the host is slow to connect to | — |
