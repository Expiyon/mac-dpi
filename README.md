# mac-dpi

**A local anti-censorship proxy for macOS.** Defeats DPI-based SNI filtering by
fragmenting the TLS ClientHello, and DNS poisoning by resolving over DoH — the
same idea as [SpoofDPI] and [GoodbyeDPI], but native to macOS and dependency-free.

[English](README.md) · [Türkçe](README.tr.md)

[![CI](https://github.com/Expiyon/mac-dpi/actions/workflows/ci.yml/badge.svg)](https://github.com/Expiyon/mac-dpi/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-macOS-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Why

GoodbyeDPI does not run on macOS (it needs a Windows kernel driver). SpoofDPI does,
but it uses a single fixed splitting method. `mac-dpi` is a pure–standard-library
Python script that:

| Censorship technique | What `mac-dpi` does |
| --- | --- |
| **SNI filtering** — the DPI box reads the hostname in the TLS ClientHello and injects a RST | Splits the ClientHello mid-hostname across both **TCP segments** *and* **separate TLS records** (`record-frag`) |
| **Plain-HTTP `Host:` filtering** | Splits the request at the `Host:` header |
| **DNS poisoning / ISP resolver blocking** | Resolves names over **DNS-over-HTTPS**; the DoH connection's own ClientHello is fragmented too |
| **RST / TLS-alert / fake-certificate injection** | Detected as a failed attempt; the next strategy is tried automatically |

TLS stays end-to-end encrypted. `mac-dpi` never sees a certificate, never decrypts
traffic, never MITMs — it only changes how the first handshake packet is *framed*.

---

## Install

Requires macOS 11+ and the system `python3` (`python3 --version`). No `pip`, no build.

```bash
git clone https://github.com/Expiyon/mac-dpi.git
cd mac-dpi
```

---

## Quick start

### Double-click

Open the folder in Finder and double-click **`dpi.command`**. A Terminal window
opens, the proxy starts, and the macOS system proxy is pointed at `127.0.0.1:8080`
automatically. Close the window (or `Ctrl+C`) and **your proxy settings are
restored to exactly what they were.**

First launch may show *"cannot verify developer"* — right-click the file → **Open**,
once. `DPI.app` does the same thing with an app icon (keep it next to `dpi.command`).

### Command line

```bash
python3 dpi.py                 # run + auto-configure the system proxy (restored on exit)
python3 dpi.py --no-set-proxy  # run the proxy only; leave system settings alone
python3 dpi.py restore         # manually restore the system proxy (recovery)
python3 dpi.py diag SITE       # diagnose why a site is blocked
python3 dpi.py test            # self-test
python3 dpi.py strategies      # list fragmentation strategies
```

Verify it works:

```bash
curl -x http://127.0.0.1:8080 -sI https://example.com
```

### Run at every login (background)

```bash
./install-service.sh      # LaunchAgent: starts at login, sets the system proxy
./uninstall-service.sh    # remove it and restore the proxy
```

---

## Diagnosing a blocked site

If something still won't load, ask the tool why:

```console
$ python3 dpi.py diag example-blocked.com     # illustrative output

=== dpi tani: example-blocked.com ===

[DNS] sistem cozumleyici : 198.51.100.10         # ISP block-page IP
[DNS] DoH (1.1.1.1 vb.)   : 203.0.113.42 ...     # real IP

[TCP] 203.0.113.42:443 ... ok (14 ms)

[TLS] parcalama YOK, dogru SNI ile      ... ClientHello sonrasi RST  ->  SNI TABANLI DPI ENGELI

[TLS] parcalama stratejileri:
     --   sni-mid        reset
     --   split-2        reset
   GECER  record-frag    ok  HTTP/1.1 200 OK
   GECER  record-tcp     ok  HTTP/1.1 200 OK

  SONUC: GECEN strateji: record-frag, record-tcp
         ->  python3 dpi.py --strategy record-frag
```

`diag` distinguishes the four cases that matter:

- **DNS tampering** — system resolver and DoH disagree → DoH is required (already the default).
- **IP null-route** — no response to the TCP SYN → *no userspace tool can fix this*; use a VPN.
- **SNI-based DPI** — RST right after the ClientHello → fragmentation gets past it; `diag` tells you which strategy.
- **MITM certificate** — a fake cert is served → a block page; DoH + fragmentation usually bypasses it.

---

## How it works

1. The browser sends `CONNECT host:443`; `mac-dpi` replies `200`.
2. `host` is resolved over **DoH** (Cloudflare + Google, automatic fallback, A + AAAA).
3. The browser's first packet — the **TLS ClientHello** — is read and its SNI
   extension is located.
4. The ClientHello is sent according to the current strategy:
   - **TCP split** — `TCP_NODELAY` is on, so each `send()` is its own segment;
     there is a ~4 ms gap between fragments so a DPI box can't re-buffer them.
   - **TLS record fragmentation** — the handshake payload is re-framed into two
     valid `0x16` TLS records. A middlebox that reassembles the TCP stream but not
     TLS records still can't see the hostname.
5. From there the connection is a transparent bidirectional tunnel.

### Adaptive engine

In `auto` mode (default) the order is:

```
record-frag → record-tcp → record-frag-3 → sni-mid → split-2 → multi → oob-mid → byte-1 → sni-1 → none
```

If a host has a remembered strategy it is tried first. The ClientHello is sent; if
a valid **ServerHello** comes back it's a success. On RST / close / TLS-alert the
socket is dropped and the next strategy is tried on a fresh connection — the
browser never notices. The winning strategy is written to
`~/.config/dpi/learned.json`, so subsequent connections to that host are instant.

### Strategies

| Name | Description |
| --- | --- |
| `record-frag` | Split the ClientHello into two separate TLS records |
| `record-tcp` | Record split + TCP-split each record at 1 byte |
| `record-frag-3` | Split into three TLS records |
| `sni-mid` | One TCP split in the middle of the SNI hostname |
| `split-2` / `split-3` | Split after the first 2 / 3 bytes (breaks the TLS record header) |
| `multi` | Split the record header and the SNI at the same time (multi-point) |
| `oob` / `oob-mid` | Split + a `MSG_OOB` urgent byte in between (TCB desync) |
| `sni-1` | Send the SNI hostname one byte per TCP segment |
| `byte-1` | Send the whole ClientHello one byte at a time (most aggressive) |
| `none` | Passthrough (control) |

---

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--listen ADDR` | `127.0.0.1:8080` | Listen address |
| `--strategy NAME` | `auto` | `auto`, or pin one of the strategies above |
| `--delay-ms N` | `0` | Extra gap between fragments (ms). Try `25`–`40` against stubborn DPI |
| `--max-attempts N` | `8` | Strategies to try in `auto` mode |
| `--probe-timeout SEC` | `2.5` | How long a strategy has to prove itself |
| `--max-conns N` | `512` | Concurrent connection ceiling |
| `--no-set-proxy` | — | Don't touch the macOS system proxy |
| `--service NAME` | auto | Network service for the system proxy (`Wi-Fi`, …) |
| `--no-doh` | — | Use the system resolver instead of DoH |
| `--doh-url URL` | Cloudflare + Google | DoH endpoint, repeatable (JSON API) |
| `--doh-strategy NAME` | `sni-mid` | Fragmentation strategy for the DoH connection |
| `--fresh` | — | Ignore learned strategies |
| `-v` / `-q` | — | Verbose / quiet |

> CLI messages are currently in Turkish (the tool's primary audience). The code,
> option names, and this README are in English.

---

## Safety & recovery

- The full pre-existing proxy configuration is saved to
  `~/.config/dpi/proxy-backup.json` before any change and restored on exit
  (`Ctrl+C`, window close, `kill`).
- If the process is killed hard, the backup is restored on the next run, or with
  `python3 dpi.py restore` (`sudo` if your macOS asks for it).
- If the previous configuration already pointed at a loopback proxy, it's backed
  up as *off* — so a dead local proxy can never strand your connection.

---

## Limitations

- **IP-level blocks** (the site's IP is null-routed): no userspace tool can help.
  `diag` reports this as *"no response to SYN"* — use a VPN / Tor / Xray.
- **If DoH itself is blocked** and DNS is poisoned: try
  `--doh-url https://8.8.8.8/resolve`, otherwise a VPN.
- **Fake-packet / low-TTL / TCP desync** (GoodbyeDPI, [zapret]) need raw sockets
  and root. This tool does not do that class of technique beyond `MSG_OOB`. If no
  `record-*` / `split` / `oob` strategy gets through, move to zapret or a VPN.
- This is **not a VPN** — it does not hide your IP address.
- The plain-HTTP path is minimal: one request per connection (`Connection: close`).

---

## Disclaimer

`mac-dpi` exists to reach the open internet where it is censored. Use it on your
own devices and in accordance with the laws that apply to you. It is provided
as-is, with no warranty.

## License

[MIT](LICENSE)

[SpoofDPI]: https://github.com/xvzc/SpoofDPI
[GoodbyeDPI]: https://github.com/ValdikSS/GoodbyeDPI
[zapret]: https://github.com/bol-van/zapret
