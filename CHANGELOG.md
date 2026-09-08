# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/1.1.0/).

## [2.0.0] - 2026-09-08

### Added
- **Adaptive strategy engine.** On a blocked host the proxy transparently retries
  the ClientHello with the next fragmentation strategy on a fresh socket, then
  remembers the one that worked in `~/.config/dpi/learned.json`.
- **TLS *record* fragmentation** (`record-frag`, `record-tcp`, `record-frag-3`) —
  splits the ClientHello across separate TLS records, not just TCP segments.
  Beats DPI that reassembles the TCP stream.
- **`MSG_OOB` desync** strategies (`oob`, `oob-mid`).
- **DPI injection detection** — a TLS `alert` or non-ServerHello reply on :443 is
  treated as a failed attempt.
- **Fragmented DNS-over-HTTPS** with multi-endpoint fallback
  (Cloudflare 1.1.1.1/1.0.0.1, Google 8.8.8.8/8.8.4.4) and AAAA support. The DoH connection's own
  ClientHello is fragmented too.
- **`diag <host>`** command — classifies the block (DNS tampering / IP
  null-route / SNI-DPI / MITM certificate) and reports which strategy passes.
- **Crash-safe macOS system-proxy automation.** Previous proxy settings are
  saved to `~/.config/dpi/proxy-backup.json` and restored on exit, on the next
  run after a crash, or via `dpi.py restore`. Loopback proxies are sanitised so
  a dead local proxy can't strand connectivity.
- **One-click launchers**: `dpi.command`, `DPI.app`, and a LaunchAgent installer.
- Startup self-test.
- `--version`.

### Changed
- `auto` order now leads with the record-fragmentation strategies.
- Minimum ~4 ms gap between fragments to guarantee TCP segmentation.
- Defaults: `--max-attempts 8`, `--probe-timeout 2.5`.
- DoH endpoints are now Cloudflare (`1.1.1.1`, `1.0.0.1`) + Google
  (`8.8.8.8`, `8.8.4.4`); Quad9 dropped (its `/dns-query` rejects the
  HTTP/1.1 JSON request with `505`).

### Fixed
- **File-descriptor leak** in the DoH / diagnostic TLS client: a failed
  handshake no longer leaks the socket. This was the cause of
  `OSError: [Errno 24] Too many open files` (and the resolver failures
  that cascade from it) during long sessions.
- Raise `RLIMIT_NOFILE` on startup — macOS gives a launchd/Terminal
  process only 256 by default, far too few for a system-wide proxy.
- Bounded concurrency (`--max-conns`, default 512) so a burst of
  background traffic can't exhaust sockets.
- Resolver failures are now rate-limited in the log instead of flooding
  it one line per unresolved host.
- DoH: an endpoint that answers "no such name" is authoritative — stop
  instead of re-querying every other resolver. Per-query DoH timeout
  capped at 5 s. A bogus / mistyped domain now fails fast (~0.2 s)
  instead of stacking up handshakes.
- The rate-limited resolver summary fires on the first failure (the
  `time.monotonic()` epoch is process-relative on macOS, so the old
  zero-init suppressed it for the first 20 s).

### Tests
- `tests/test_dpi.py` — 35 offline unit tests (SNI parsing, every
  fragmentation strategy round-trips, learn store, `_order_for`, the
  rate limiter, `SysProxy` enable/restore round-trip stubbed, DoH
  short-circuit, an fd-leak regression test, CLI parsing). Wired into CI
  on Python 3.8–3.12 and macOS.
- `tests/integration.sh` — 41 live checks (proxy matrix incl. a censored
  site, every forced strategy, adaptive fallback, concurrency, fd
  stability, `diag`, graceful shutdown). Not in CI (needs open network).

## [1.0.0] - 2026-09-08

### Added
- Initial release: local HTTP/HTTPS proxy with SNI-aware ClientHello splitting
  and DNS-over-HTTPS resolution.
