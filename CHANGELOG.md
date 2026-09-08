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
  (1.1.1.1 / 9.9.9.9 / 8.8.8.8) and AAAA support. The DoH connection's own
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

## [1.0.0] - 2026-09-08

### Added
- Initial release: local HTTP/HTTPS proxy with SNI-aware ClientHello splitting
  and DNS-over-HTTPS resolution.
