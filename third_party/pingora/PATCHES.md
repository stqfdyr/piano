# Pingora fork

A trimmed copy of [cloudflare/pingora](https://github.com/cloudflare/pingora), used as
path dependencies by the piano workspace. It is its own Cargo workspace (excluded from
the root one) so that the upstream manifests, `workspace = true` inheritance and
formatting settings work unchanged.

- Upstream: `https://github.com/cloudflare/pingora`
- Base commit: `3f87e92c982ee27c714506e16ae362776faea4aa` (2026-11-09, workspace version 0.9.0)
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
| P2 | rustls injection points: `TlsSettings::with_server_config(Arc<ServerConfig>)` for listeners; `ConnectorOptions::rustls_client_config` (config + root store) for the upstream connector | The caller needs its own certificate resolver (SNI table, hot reload), ALPN, session tickets, and extra roots added to (not replacing) the system roots | — |
