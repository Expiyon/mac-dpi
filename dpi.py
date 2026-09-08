#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dpi - macOS icin yerel DPI-atlatma proxy'si.  (SpoofDPI / GoodbyeDPI mantiginda)

SpoofDPI'ye gore farklari
-------------------------
  * Uyarlanabilir strateji motoru: bir alan adi bloklaniyorsa baglantiyi
    kapatmadan bir sonraki parcalama yontemini dener ve ise yarayani
    ~/.config/dpi/learned.json icine ogrenir. Sonraki seferde dogrudan onu kullanir.
  * TLS *kayit* parcalama (record fragmentation): ClientHello'yu sadece TCP
    segmentine degil, ayri TLS kayitlarina da boler. TCP birlestirme yapan
    DPI'lari da gecer.
  * DPI enjeksiyonu tespiti: 443'te ServerHello yerine TLS alert / blok sayfasi
    gelirse "gecmedi" sayar ve baska strateji dener.
  * DNS-over-HTTPS'in kendisi de parcali gonderilir; birden fazla cozumleyici
    (1.1.1.1 / 1.0.0.1 / 8.8.8.8 / 8.8.4.4) arasinda otomatik gecis. AAAA (IPv6) destegi.
  * Sistem proxy'sini otomatik ayarlar ve cikista *onceki haline* geri yukler.
    Cokme olsa bile ~/.config/dpi/proxy-backup.json ile bir sonraki calismada
    veya `python3 dpi.py restore` ile kurtarilir.
  * Acilista kendi kendini test eder ("parcali TLS gercekten calisiyor mu").

Tek dosya, saf standart kutuphane. Python 3.8+. Kurulum yok.

Kullanim
--------
  python3 dpi.py                 # 127.0.0.1:8080 dinler + sistem proxy'sini ayarlar
  python3 dpi.py --no-set-proxy  # sadece proxy'yi calistir, sisteme dokunma
  python3 dpi.py restore         # sistem proxy'sini elle geri yukle
  python3 dpi.py test            # kendi kendine test
  python3 dpi.py strategies      # strateji listesi

Ya da:  dpi.command dosyasina (veya DPI.app) cift tikla.
"""

__version__ = "2.0.0"

import argparse
import asyncio
import atexit
import json
import logging
import os
import resource
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

CONFIG_DIR = Path(os.environ.get("DPI_HOME") or (Path.home() / ".config" / "dpi"))
LEARN_FILE = CONFIG_DIR / "learned.json"
BACKUP_FILE = CONFIG_DIR / "proxy-backup.json"

DOH_ENDPOINTS = [
    "https://1.1.1.1/dns-query",     # Cloudflare
    "https://1.0.0.1/dns-query",     # Cloudflare (ikincil)
    "https://8.8.8.8/resolve",       # Google
    "https://8.8.4.4/resolve",       # Google (ikincil)
]

LOG = logging.getLogger("dpi")
_TTY = sys.stdout.isatty()


def raise_fd_limit(target=16384):
    """Acik dosya (soket) limitini yukselt. macOS varsayilani cok dusuk (256);
    sistem proxy'si olarak calisirken 'Too many open files' verir."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return None
    if soft != resource.RLIM_INFINITY and soft >= target:
        return soft
    tries = [target, 10240, 8192, 4096, 2048]
    if hard != resource.RLIM_INFINITY:
        tries = [t for t in tries if t <= hard] or [hard]
    for want in tries:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            return want
        except (ValueError, OSError):
            continue
    return soft


def _c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if _TTY else txt


def _ok(msg):
    LOG.info("%s %s", _c("OK", "32;1"), msg)


def _warn(msg):
    LOG.warning("%s %s", _c("!", "33;1"), msg)


# ===========================================================================
# 1) TLS ClientHello ayristirma + parcalama stratejileri
# ===========================================================================
def sni_span(hello: bytes):
    """ClientHello icinde SNI host adinin (baslangic, bitis) mutlak bayt konumu."""
    try:
        if len(hello) < 44 or hello[0] != 0x16 or hello[5] != 0x01:
            return None
        pos = 43                                              # kayit(5)+hs(4)+sur(2)+random(32)
        pos += 1 + hello[pos]                                 # session id
        pos += 2 + int.from_bytes(hello[pos:pos + 2], "big")  # cipher suites
        pos += 1 + hello[pos]                                 # compression
        if pos + 2 > len(hello):
            return None
        ext_end = min(len(hello), pos + 2 + int.from_bytes(hello[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= ext_end:
            etype = int.from_bytes(hello[pos:pos + 2], "big")
            elen = int.from_bytes(hello[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x0000:                               # server_name
                p = pos + 2                                   # liste uzunlugunu atla
                if p + 3 > len(hello) or hello[p] != 0:
                    return None
                nlen = int.from_bytes(hello[p + 1:p + 3], "big")
                p += 3
                if p + nlen > len(hello):
                    return None
                return (p, p + nlen)
            pos += elen
        return None
    except Exception:
        return None


def _tcp_split(data: bytes, points):
    pts = sorted({p for p in points if 0 < p < len(data)})
    out, prev = [], 0
    for p in pts:
        out.append(data[prev:p])
        prev = p
    out.append(data[prev:])
    return [c for c in out if c]


def _record_split(hello: bytes, cut_points):
    """Tek bir TLS kaydini, handshake yukunu `cut_points`tan bolerek birden fazla
    TLS kaydina yeniden paketler.  head = 0x16 0x03 0x01."""
    if len(hello) < 6 or hello[0] != 0x16:
        return [hello]
    head = hello[:3]
    payload = hello[5:]
    n = len(payload)
    cuts = sorted({k for k in cut_points if 0 < k < n})
    recs, prev = [], 0
    for k in cuts:
        seg = payload[prev:k]
        recs.append(head + len(seg).to_bytes(2, "big") + seg)
        prev = k
    seg = payload[prev:]
    recs.append(head + len(seg).to_bytes(2, "big") + seg)
    return recs


OOB = object()   # "araya MSG_OOB (acil) bayt gonder" isaretcisi

STRATEGIES = {
    "none":          "hicbir sey yapma (kontrol)",
    "sni-mid":       "ClientHello'yu SNI adinin ortasindan tek noktadan TCP-bol",
    "split-2":       "ilk 2 bayttan sonra bol (TLS kayit basligini parcala)",
    "split-3":       "ilk 3 bayttan sonra bol",
    "multi":         "ayni anda hem kayit basligini hem SNI'yi bol (cok noktali)",
    "sni-1":         "SNI adini bayt bayt ayri TCP segmentlerine bol",
    "record-frag":   "ClientHello'yu iki ayri TLS kaydina bol",
    "record-frag-3": "ClientHello'yu uc ayri TLS kaydina bol",
    "record-tcp":    "TLS kayit bolme + her kaydi ayrica 1 bayttan TCP-bol",
    "oob":           "kayit basligini bol + araya MSG_OOB bayt (DPI TCB desync)",
    "oob-mid":       "SNI ortasindan bol + araya MSG_OOB bayt",
    "byte-1":        "tum ClientHello'yu bayt bayt gonder (en agresif)",
    "split-4":       "her 4 baytta bir TCP-bol",
}

# auto modda deneme sirasi. TLS *kayit* parcalama (record-*) modern SNI DPI'sini
# (TR, RU) en cok geciren yontemdir; basa aliyoruz.
DEFAULT_ORDER = [
    "record-frag", "record-tcp", "record-frag-3", "sni-mid", "split-2",
    "multi", "oob-mid", "byte-1", "sni-1", "none",
]


def plan(hello: bytes, strategy: str):
    """Stratejiye gore 'islem' listesi dondurur: her oge ya bytes (gonder) ya da
    OOB isaretcisi (araya bir acil/urgent bayt gonder)."""
    span = sni_span(hello)
    if span:
        s, e = span
    else:
        s = e = max(1, min(len(hello) // 2, 64))
    mid = s + max(1, (e - s) // 2)

    if strategy == "none":
        return [hello]
    if strategy == "sni-mid":
        return _tcp_split(hello, [mid])
    if strategy == "split-2":
        return _tcp_split(hello, [2])
    if strategy == "split-3":
        return _tcp_split(hello, [3])
    if strategy == "multi":
        return _tcp_split(hello, [3, s, mid, e])
    if strategy == "sni-1":
        return _tcp_split(hello, [s] + list(range(s, e)) + [e])
    if strategy == "byte-1":
        return [hello[i:i + 1] for i in range(len(hello))]
    if strategy == "record-frag":
        return _record_split(hello, [mid - 5])
    if strategy == "record-frag-3":
        return _record_split(hello, [s - 5 + (e - s) // 3, s - 5 + 2 * (e - s) // 3])
    if strategy == "record-tcp":
        out = []
        for r in _record_split(hello, [mid - 5]):
            out += ([r[:1], r[1:]] if len(r) > 1 else [r])
        return out
    if strategy == "oob":
        return [hello[:3], OOB, hello[3:]]
    if strategy == "oob-mid":
        return [hello[:mid], OOB, hello[mid:]]
    if strategy.startswith("split-"):
        n = max(1, int(strategy.split("-")[1]))
        return [hello[i:i + n] for i in range(0, len(hello), n)]
    return [hello]


def build_chunks(hello: bytes, strategy: str):
    """plan()'in yalniz bayt ogeleri (OOB kullanmayan yollar icin: HTTP, DoH, test)."""
    return [x for x in plan(hello, strategy) if isinstance(x, (bytes, bytearray))]


def _looks_serverhello(d: bytes):
    return len(d) >= 3 and d[0] == 0x16 and d[1] == 0x03


def _looks_alert(d: bytes):
    return len(d) >= 3 and d[0] == 0x15 and d[1] == 0x03


# ===========================================================================
# 2) ClientHello'yu parcalayan bloklamayan TLS istemcisi (DoH + kendi testi)
# ===========================================================================
class FragTLS:
    """MemoryBIO ile el sikismayi kendimiz surerek ClientHello'yu parcalar.
    Bloklayan API; event loop disinda (executor) kullanilir."""

    def __init__(self, sock, server_hostname, chunks_fn, timeout, verify=True, gap=0.004):
        self.sock = sock
        self.sock.settimeout(timeout)
        self._gap = gap
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=server_hostname)
        self._chunks_fn = chunks_fn
        self._first = True
        try:
            self._handshake()
        except BaseException:
            self.close()          # el sikisma basarisizsa soketi sizdirma
            raise

    def _flush(self):
        data = self._out.read()
        if not data:
            return
        if self._first and data[:1] == b"\x16":
            self._first = False
            chunks = [c for c in self._chunks_fn(data) if c]
            for i, ch in enumerate(chunks):
                self.sock.sendall(ch)
                if self._gap and i != len(chunks) - 1:
                    time.sleep(self._gap)
        else:
            self.sock.sendall(data)

    def _pump(self):
        b = self.sock.recv(65536)
        if not b:
            raise ssl.SSLError("TLS: baglanti kapandi")
        self._in.write(b)

    def _handshake(self):
        while True:
            try:
                self._obj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._pump()
            except ssl.SSLWantWriteError:
                self._flush()

    def sendall(self, data: bytes):
        n = 0
        while n < len(data):
            try:
                n += self._obj.write(data[n:])
                self._flush()
            except ssl.SSLWantReadError:
                self._flush()
                self._pump()
            except ssl.SSLWantWriteError:
                self._flush()

    def recv(self, n=65536) -> bytes:
        while True:
            try:
                return self._obj.read(n)
            except ssl.SSLWantReadError:
                self._flush()
                try:
                    self._pump()
                except (ssl.SSLError, OSError):
                    return b""
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                return b""

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def _http_get_over(tls: FragTLS, host_header: str, path: str):
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        "Accept: application/dns-json\r\nUser-Agent: dpi/2\r\n"
        "Connection: close\r\n\r\n"
    )
    tls.sendall(req.encode("ascii"))
    buf = b""
    while True:
        c = tls.recv(65536)
        if not c:
            break
        buf += c
    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line:
        raise RuntimeError(f"HTTP {status_line!r}")
    if b"transfer-encoding: chunked" in head.lower():
        body = _dechunk(body)
    return body


def _dechunk(data: bytes) -> bytes:
    out, i = b"", 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(data[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += data[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out


# ===========================================================================
# 3) DNS-over-HTTPS cozumleyici
# ===========================================================================
class Resolver:
    def __init__(self, endpoints, use_doh, strategy, timeout, loop):
        self.endpoints = endpoints
        self.use_doh = use_doh
        self.strategy = strategy
        self.timeout = timeout
        self.loop = loop
        self.cache = {}   # host -> (ips, expiry)

    async def resolve(self, host: str):
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(fam, host)
                return [host]
            except OSError:
                pass

        now = time.time()
        hit = self.cache.get(host)
        if hit and hit[1] > now:
            return hit[0]

        ips = []
        if self.use_doh:
            try:
                ips = await self.loop.run_in_executor(None, self._doh_all, host)
            except Exception as e:
                LOG.debug("DoH hata (%s): %s", host, e)

        if not ips:
            try:
                infos = await self.loop.getaddrinfo(
                    host, None, type=socket.SOCK_STREAM
                )
                seen = []
                for fam, *_x, sa in infos:
                    ip = sa[0]
                    if ip not in seen:
                        seen.append(ip)
                ips = seen
            except Exception as e:
                raise RuntimeError(f"cozumlenemedi: {e}")

        if not ips:
            raise RuntimeError("A/AAAA kaydi yok")
        # IPv4'u tercih et
        ips.sort(key=lambda x: (":" in x))
        self.cache[host] = (ips, now + 300)
        return ips

    def _doh_all(self, host):
        for ep in self.endpoints:
            u = urlsplit(ep)
            ip, port = u.hostname, (u.port or 443)
            results = []
            for rtype in ("A", "AAAA"):
                try:
                    raw = socket.create_connection((ip, port), timeout=self.timeout)
                    tls = FragTLS(raw, ip,
                                  lambda d: build_chunks(d, self.strategy),
                                  self.timeout, verify=True)
                    body = _http_get_over(tls, ip, f"{u.path}?name={host}&type={rtype}")
                    tls.close()
                    obj = json.loads(body)
                    want = 1 if rtype == "A" else 28
                    for ans in obj.get("Answer", []):
                        if ans.get("type") == want:
                            results.append(ans["data"])
                except Exception as e:
                    LOG.debug("DoH %s %s/%s: %s", ep, host, rtype, e)
            if results:
                return results
        return []


# ===========================================================================
# 4) Ogrenme deposu
# ===========================================================================
class LearnStore:
    TTL = 7 * 86400

    def __init__(self, path: Path, fresh=False):
        self.path = path
        self.data = {}
        self.dirty = False
        if not fresh and path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                self.data = {}

    def get(self, host):
        e = self.data.get(host)
        if e and time.time() - e.get("ts", 0) < self.TTL:
            return e.get("strategy")
        return None

    def record(self, host, strategy):
        e = self.data.get(host)
        if not e or e.get("strategy") != strategy or time.time() - e.get("ts", 0) > 3600:
            self.data[host] = {"strategy": strategy, "ts": int(time.time())}
            self.dirty = True

    def flush(self):
        if not self.dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=1, sort_keys=True))
            self.dirty = False
        except Exception:
            pass


# ===========================================================================
# 5) Proxy
# ===========================================================================
def _w(writer, data):
    try:
        writer.write(data)
    except Exception:
        pass


def _close(writer):
    try:
        writer.close()
    except Exception:
        pass


def _nodelay(writer):
    try:
        s = writer.get_extra_info("socket")
        if s is not None:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def _split_hostport(s: str, default: int):
    s = s.strip()
    if s.startswith("["):
        h, _, rest = s[1:].partition("]")
        p = rest[1:] if rest.startswith(":") else ""
        return h, int(p) if p.isdigit() else default
    if s.count(":") == 1:
        h, _, p = s.partition(":")
        return h, int(p) if p.isdigit() else default
    return s, default


class Proxy:
    def __init__(self, resolver, learn, strategy, delay_ms, timeout,
                 probe_timeout, max_attempts, max_conns=512):
        self.resolver = resolver
        self.learn = learn
        self.strategy = strategy          # "auto" veya sabit bir strateji adi
        self.delay = delay_ms / 1000.0
        self.timeout = timeout
        self.probe_timeout = probe_timeout
        self.max_attempts = max_attempts
        self.sem = asyncio.Semaphore(max_conns)
        self.stats = {"conns": 0, "bypassed": 0, "failed": 0}
        self._rfail_t = 0.0              # son ozet zamani
        self._rfail_n = 0               # o zamandan beri cozulemeyen host sayisi

    def _resolve_failed(self, host, e):
        """Cozumleme hatasi: her host icin debug; INFO'da en fazla ~20 sn'de bir ozet."""
        LOG.debug("%s cozulemedi: %s", host, e)
        self._rfail_n += 1
        now = time.monotonic()
        if now - self._rfail_t >= 20:
            LOG.info("cozumlenemeyen alan adi: %d (son ~20 sn, sonuncu: %s)",
                     self._rfail_n, host)
            self._rfail_t = now
            self._rfail_n = 0

    # --------------------------------------------------------------------- #
    async def handle(self, creader, cwriter):
        if self.sem.locked():
            LOG.debug("es zamanli baglanti siniri doldu, bekleniyor")
        async with self.sem:
            await self._handle(creader, cwriter)

    async def _handle(self, creader, cwriter):
        try:
            try:
                header = await asyncio.wait_for(
                    creader.readuntil(b"\r\n\r\n"), timeout=self.timeout
                )
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    asyncio.TimeoutError, ConnectionResetError, OSError):
                return
            line = header.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
            if len(line) != 3:
                return
            method, target, _ = line
            if method.upper() == "CONNECT":
                await self._connect(creader, cwriter, target, header)
            else:
                await self._http(creader, cwriter, method, target, header)
        except Exception as e:
            LOG.debug("baglanti hatasi: %s", e)
        finally:
            _close(cwriter)

    # --------------------------------------------------------------------- #
    async def _read_hello(self, reader):
        try:
            buf = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            return b""
        if not buf or buf[0] != 0x16 or len(buf) < 5:
            return buf
        want = 5 + int.from_bytes(buf[3:5], "big")
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 0.2
        while len(buf) < want:
            try:
                more = await asyncio.wait_for(
                    reader.read(65536), timeout=max(0.0, deadline - loop.time())
                )
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                break
            if not more:
                break
            buf += more
        return buf

    def _order_for(self, host):
        if self.strategy != "auto":
            return [self.strategy]
        order = list(DEFAULT_ORDER)
        learned = self.learn.get(host)
        if learned in order:
            order.remove(learned)
            order.insert(0, learned)
        order = order[: self.max_attempts]
        if "none" not in order:            # duz gecis her zaman son care olsun
            order.append("none")
        return order

    async def _send_chunks(self, writer, chunks):
        real = [c for c in chunks if isinstance(c, (bytes, bytearray)) and c]
        last = len(real) - 1
        for i, ch in enumerate(real):
            writer.write(ch)
            await writer.drain()
            if self.delay and i != last:
                await asyncio.sleep(self.delay)

    async def _prime(self, loop, ip, port, hello, name):
        """Ham soketle baglan, stratejiyi uygula (OOB dahil), ilk cevabi oku.
        (sock, data) dondurur; basarisizsa (None, b'')."""
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ops = plan(hello, name)
            reals = [o for o in ops if o is OOB or (isinstance(o, (bytes, bytearray)) and o)]
            # parcalar arasi en az ~4ms: TCP segmentlerinin gercekten ayrilmasini
            # ve DPI'nin yeniden birlestirememesini garanti eder.
            gap = max(self.delay, 0.004) if len(reals) > 1 else 0.0
            for i, op in enumerate(reals):
                if op is OOB:
                    try:
                        sock.send(b"\x00", socket.MSG_OOB)
                    except (BlockingIOError, OSError):
                        pass
                else:
                    await loop.sock_sendall(sock, op)
                if gap and i != len(reals) - 1:
                    await asyncio.sleep(gap)
            data = b""
            deadline = loop.time() + self.probe_timeout
            while loop.time() < deadline:
                try:
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(sock, 8192),
                        timeout=max(0.05, deadline - loop.time()),
                    )
                except (asyncio.TimeoutError, ConnectionResetError, OSError):
                    break
                if not chunk:
                    break
                data += chunk
                if _looks_serverhello(data) or _looks_alert(data) or len(data) >= 16:
                    break
            return sock, data
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            return None, b""

    # --------------------------------------------------------------------- #
    async def _connect(self, creader, cwriter, target, _header):
        host, port = _split_hostport(target, 443)
        try:
            ips = await self.resolver.resolve(host)
        except Exception as e:
            self._resolve_failed(host, e)
            _w(cwriter, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        _w(cwriter, b"HTTP/1.1 200 Connection established\r\n\r\n")
        await cwriter.drain()

        hello = await self._read_hello(creader)
        if not hello:
            return

        loop = asyncio.get_event_loop()
        order = self._order_for(host)
        chosen = None
        tried = []
        for name in order:
            for ip in ips[:3]:
                tried.append(name)
                sock, data = await self._prime(loop, ip, port, hello, name)
                if sock is None:
                    continue
                good = _looks_serverhello(data) if port == 443 else bool(data)
                if good:
                    try:
                        sr, sw = await asyncio.open_connection(sock=sock)
                        chosen = (sr, sw, name, data)
                    except Exception:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    break
                try:
                    sock.close()
                except OSError:
                    pass
                if _looks_alert(data):
                    LOG.debug("%s: TLS-alert enjeksiyonu (%s)", host, name)
            if chosen:
                break

        if not chosen:
            self.stats["failed"] += 1
            LOG.warning("%s: hicbir strateji gecmedi [%s]", host,
                        ", ".join(dict.fromkeys(tried)) or "-")
            # 200'u zaten yolladik; temiz cikis = baglantiyi kapatmak
            return

        sr, sw, name, data = chosen
        self.stats["conns"] += 1
        needed_fallback = len(dict.fromkeys(tried)) > 1
        self.learn.record(host, name)
        if needed_fallback:
            self.stats["bypassed"] += 1
            LOG.info("%-40s %s %s  %s", host, _c("=>", "36"), _c(name, "32;1"),
                     _c("(blok asildi)", "33"))
        else:
            LOG.debug("%s => %s", host, name)

        cwriter.write(data)
        await cwriter.drain()
        await self._relay(creader, cwriter, sr, sw)

    # --------------------------------------------------------------------- #
    async def _http(self, creader, cwriter, method, target, header):
        u = urlsplit(target)
        host = u.hostname
        if not host:
            return
        port = u.port or 80
        path = (u.path or "/") + (("?" + u.query) if u.query else "")

        head_txt = header.decode("latin-1")
        lines = head_txt.split("\r\n")
        out = [f"{method} {path} HTTP/1.1"]
        have_host = False
        body_len = 0
        for ln in lines[1:]:
            if not ln:
                continue
            name = ln.split(":", 1)[0].strip().lower()
            if name in ("proxy-connection", "connection"):
                continue
            if name == "host":
                have_host = True
            if name == "content-length":
                try:
                    body_len = int(ln.split(":", 1)[1])
                except ValueError:
                    body_len = 0
            out.append(ln)
        if not have_host:
            out.insert(1, f"Host: {host}")
        out.append("Connection: close")
        raw = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")

        body = b""
        if body_len > 0:
            try:
                body = await asyncio.wait_for(
                    creader.readexactly(body_len), timeout=self.timeout
                )
            except Exception:
                body = b""

        try:
            ips = await self.resolver.resolve(host)
        except Exception as e:
            self._resolve_failed(host, e)
            _w(cwriter, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        low = raw.lower()
        h = low.find(b"host: ")
        host_split = _tcp_split(raw, [h + 6, h + 6 + max(1, len(host) // 2)]) if h != -1 else [raw]

        sr = sw = None
        for variant in (host_split, [raw]):          # once Host-satiri bol, olmazsa duz
            for ip in ips[:3]:
                try:
                    sr, sw = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=self.timeout
                    )
                except Exception:
                    sr = sw = None
                    continue
                _nodelay(sw)
                try:
                    await self._send_chunks(sw, variant)
                    if body:
                        sw.write(body)
                        await sw.drain()
                except Exception:
                    _close(sw)
                    sr = sw = None
                    continue
                break
            if sw is not None:
                break

        if sw is None:
            LOG.warning("%s: HTTP baglantisi kurulamadi", host)
            _w(cwriter, b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        self.stats["conns"] += 1
        LOG.debug("%s (http) => host-split", host)
        await self._relay(creader, cwriter, sr, sw)

    # --------------------------------------------------------------------- #
    async def _relay(self, creader, cwriter, sreader, swriter):
        t1 = asyncio.create_task(_pipe(creader, swriter))
        t2 = asyncio.create_task(_pipe(sreader, cwriter))
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        _close(swriter)
        _close(cwriter)
        await asyncio.gather(t1, t2, return_exceptions=True)


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        _close(writer)


# ===========================================================================
# 6) macOS sistem proxy'si  (kaydet / uygula / geri yukle)
# ===========================================================================
class SysProxy:
    LOCAL_BYPASS = ["localhost", "127.0.0.1", "*.local", "169.254/16", "::1"]
    _LOOPBACK = ("127.", "::1", "localhost", "0.0.0.0")

    @classmethod
    def _sanitize_backup(cls, st):
        """Onceki durum zaten bir yerel proxy'ye (127.x / ::1) isaret ediyorsa
        onu yedege 'kapali' olarak yaz: aksi halde geri yukleme, olu bir yerel
        proxy'yi geri getirip interneti kesebilir."""
        for key in ("web", "secure"):
            srv = (st[key].get("server") or "").strip().lower()
            if srv.startswith(cls._LOOPBACK):
                st[key] = {"enabled": False, "server": "", "port": "0"}
        return st

    @staticmethod
    def _ns(*args, check=True):
        return subprocess.run(["networksetup", *args], check=check,
                              capture_output=True, text=True)

    @classmethod
    def primary_service(cls):
        try:
            route = subprocess.run(["route", "-n", "get", "default"],
                                   capture_output=True, text=True).stdout
        except Exception:
            return None
        iface = None
        for ln in route.splitlines():
            ln = ln.strip()
            if ln.startswith("interface:"):
                iface = ln.split(":", 1)[1].strip()
        if not iface:
            return None
        try:
            order = cls._ns("-listnetworkserviceorder").stdout
        except Exception:
            return None
        cur = None
        import re
        for ln in order.splitlines():
            m = re.match(r"\(\d+\)\s+(.*)", ln.strip())
            if m:
                cur = m.group(1).strip()
            elif f"Device: {iface})" in ln and cur:
                return cur
        return None

    @classmethod
    def _get_block(cls, flag, svc):
        d = {}
        for ln in cls._ns(flag, svc).stdout.splitlines():
            if ":" in ln:
                k, _, v = ln.partition(":")
                d[k.strip().lower()] = v.strip()
        return {
            "enabled": d.get("enabled", "").lower().startswith("yes"),
            "server": d.get("server", ""),
            "port": d.get("port", "0") or "0",
        }

    @classmethod
    def read_state(cls, svc):
        bp = []
        for ln in cls._ns("-getproxybypassdomains", svc).stdout.splitlines():
            ln = ln.strip()
            if ln and "aren't any" not in ln.lower():
                bp.append(ln)
        return {
            "service": svc,
            "web": cls._get_block("-getwebproxy", svc),
            "secure": cls._get_block("-getsecurewebproxy", svc),
            "bypass": bp,
        }

    @classmethod
    def apply_state(cls, st):
        svc = st["service"]
        for setflag, key in (("-setwebproxy", "web"), ("-setsecurewebproxy", "secure")):
            b = st[key]
            if b["server"]:
                cls._ns(setflag, svc, b["server"], str(b["port"] or "0"))
        cls._ns("-setwebproxystate", svc, "on" if st["web"]["enabled"] else "off")
        cls._ns("-setsecurewebproxystate", svc, "on" if st["secure"]["enabled"] else "off")
        cls._ns("-setproxybypassdomains", svc, *(st["bypass"] or ["Empty"]))

    @classmethod
    def enable(cls, listen_host, listen_port, service=None):
        # onceki cokmeden kalan yedek varsa once onu geri yukle
        if BACKUP_FILE.exists():
            try:
                cls.restore(silent=True)
                LOG.info("onceki oturumdan kalan proxy yedegi geri yuklendi")
            except Exception:
                pass
        svc = service or cls.primary_service()
        if not svc:
            raise RuntimeError("aktif ag servisi bulunamadi (--service ile belirtin)")
        cur = cls._sanitize_backup(cls.read_state(svc))
        BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
        BACKUP_FILE.write_text(json.dumps({"ts": time.time(), "state": cur}, indent=2))
        bypass = list(dict.fromkeys(cur["bypass"] + cls.LOCAL_BYPASS))
        cls._ns("-setwebproxy", svc, listen_host, str(listen_port))
        cls._ns("-setsecurewebproxy", svc, listen_host, str(listen_port))
        cls._ns("-setwebproxystate", svc, "on")
        cls._ns("-setsecurewebproxystate", svc, "on")
        cls._ns("-setproxybypassdomains", svc, *bypass)
        return svc

    @classmethod
    def restore(cls, silent=False):
        if not BACKUP_FILE.exists():
            if not silent:
                print("geri yuklenecek yedek yok")
            return False
        data = json.loads(BACKUP_FILE.read_text())
        cls.apply_state(data["state"])
        try:
            BACKUP_FILE.unlink()
        except OSError:
            pass
        if not silent:
            print(f"sistem proxy ayarlari geri yuklendi ({data['state']['service']})")
        return True


# ===========================================================================
# 7) Kendi kendine test
# ===========================================================================
async def self_test(resolver, timeout, test_host):
    try:
        ips = await resolver.resolve(test_host)
    except Exception as e:
        _warn(f"kendi testi: DNS cozulemedi ({e})")
        return
    loop = asyncio.get_event_loop()

    def probe():
        raw = socket.create_connection((ips[0], 443), timeout=timeout)
        tls = FragTLS(raw, test_host,
                      lambda d: build_chunks(d, "sni-mid"), timeout, verify=True)
        tls.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {test_host}\r\nConnection: close\r\n\r\n".encode()
        )
        r = tls.recv(200)
        tls.close()
        return r

    try:
        r = await loop.run_in_executor(None, probe)
        if r.startswith(b"HTTP/"):
            _ok(f"kendi testi gecti - parcali TLS {test_host} uzerinden calisiyor "
                f"(cikis IP {ips[0]})")
        else:
            _warn(f"kendi testi belirsiz: {r[:40]!r}")
    except Exception as e:
        _warn(f"kendi testi basarisiz: {e}")


# ===========================================================================
# 7b) Tani (diag)
# ===========================================================================
def _tcp_probe(ip, port, timeout):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        return "ok", time.time() - t0
    except socket.timeout:
        return "timeout", None
    except ConnectionRefusedError:
        return "refused", None
    except OSError as e:
        return f"err ({e})", None
    finally:
        try:
            s.close()
        except OSError:
            pass


def _tls_probe(host, ip, strategy, timeout, verify=False, gap=0.0):
    """(durum, ayrinti). durum: ok | reset | timeout | alert | certfail | connfail | tlserr"""
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
    except socket.timeout:
        return "timeout", "TCP"
    except OSError as e:
        return "connfail", str(e)
    try:
        tls = FragTLS(raw, host, lambda d: build_chunks(d, strategy),
                      timeout, verify=verify, gap=gap)
    except ssl.SSLCertVerificationError as e:
        return "certfail", str(e)
    except socket.timeout:
        return "timeout", "handshake"
    except ConnectionResetError as e:
        return "reset", str(e)
    except ssl.SSLError as e:
        m = str(e).lower()
        if any(k in m for k in ("kapandi", "eof", "reset", "unexpected")):
            return "reset", str(e)
        if "alert" in m:
            return "alert", str(e)
        return "tlserr", str(e)
    except OSError as e:
        return "tlserr", str(e)
    try:
        tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        r = tls.recv(120)
        tls.close()
        return "ok", " ".join(r[:48].decode("latin-1", "replace").split())
    except Exception as e:
        return "ok", f"(el sikisma tamam, veri hatasi: {e})"


def cmd_diag(args):
    raw = (args.target or "").strip()
    if not raw:
        print("kullanim:  python3 dpi.py diag ornek-site.com", file=sys.stderr)
        return 2
    host = raw.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    to = args.timeout

    print(f"\n=== dpi tani: {host} ===\n")

    # 1) DNS
    sys_ips = []
    try:
        sys_ips = sorted({ai[4][0] for ai in
                          socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        print(f"[DNS] sistem cozumleyici : {', '.join(sys_ips) or '(bos)'}")
    except Exception as e:
        print(f"[DNS] sistem cozumleyici : HATA ({e})")

    doh_ips = []
    try:
        doh_ips = Resolver(args.doh_url or DOH_ENDPOINTS, True,
                           args.doh_strategy, to, None)._doh_all(host)
    except Exception as e:
        print(f"[DNS] DoH                 : HATA ({e})")
    print(f"[DNS] DoH (1.1.1.1 vb.)   : {', '.join(doh_ips) or '(BOS!)'}")

    if not doh_ips:
        print("\n  !! DoH cevap vermedi. Sansurcu DoH'yi de engelliyorsa ve DNS "
              "zehirliyorsa site acilmaz.\n     Dene: --doh-url https://8.8.8.8/resolve  |  aksi halde VPN.")
    if sys_ips and doh_ips and not (set(sys_ips) & set(doh_ips)):
        print("\n  >> Sistem DNS'i DoH'tan FARKLI IP donuyor  ->  DNS mudahalesi cok olasi. "
              "DoH sart (dpi zaten kullaniyor).")

    target_ips = doh_ips or sys_ips
    if not target_ips:
        print("\n  SONUC: alan adi hic cozulemedi.  ->  VPN/Tor gerekebilir.")
        return 1
    ip = next((x for x in target_ips if ":" not in x), target_ips[0])

    # 2) TCP
    print(f"\n[TCP] {ip}:443 ...", end=" ")
    st, dt = _tcp_probe(ip, 443, to)
    if st == "timeout":
        print("SYN'e cevap YOK")
        print("\n  SONUC: IP SEVIYESINDE ENGEL (null-route).  dpi bunu asamaz -> VPN/Tor/Xray.")
        return 1
    print(f"{st}" + (f" ({dt * 1000:.0f} ms)" if dt else ""))

    # 3) parcalama YOK
    print("\n[TLS] parcalama YOK, dogru SNI ile      ...", end=" ")
    stt, det = _tls_probe(host, ip, "none", to, verify=True)
    if stt == "ok":
        print("BASARILI")
        print("\n  SONUC: bu IP'de SNI filtresi yok. Site sadece DNS ile engelleniyordu.")
        print("         dpi'yi normal calistir (DoH acik) -> yeter.")
        return 0
    if stt == "certfail":
        print("SERTIFIKA DOGRULANMADI (araya sahte sertifika / MITM blok sayfasi olabilir)")
    elif stt == "reset":
        print("ClientHello sonrasi RST  ->  SNI TABANLI DPI ENGELI")
    elif stt == "timeout":
        print("ClientHello sonrasi sessizlik  ->  SNI tabanli engel olasi")
    elif stt == "alert":
        print("DPI TLS-alert enjekte ediyor  ->  SNI tabanli engel")
    else:
        print(f"{stt}: {det[:70]}")

    # 4) stratejiler
    print("\n[TLS] parcalama stratejileri:")
    order = ["sni-mid", "split-2", "split-3", "multi", "record-frag",
             "record-tcp", "record-frag-3", "sni-1", "byte-1"]
    winners = []
    for s in order:
        stt, det = _tls_probe(host, ip, s, to, verify=False)
        if stt == "ok":
            winners.append(s)
        print(f"   {'GECER ' if stt == 'ok' else '  --  '} {s:<14} {stt}"
              f"{'  ' + det[:40] if stt == 'ok' else ''}")

    if not winners:
        print("\n   + parcalar arasi 25 ms gecikme ile:")
        for s in ("sni-mid", "multi", "record-frag", "record-tcp"):
            stt, _d = _tls_probe(host, ip, s, to, verify=False, gap=0.025)
            if stt == "ok":
                winners.append(s + " --delay-ms 25")
            print(f"   {'GECER ' if stt == 'ok' else '  --  '} {s:<14} {stt} (+25ms)")

    print()
    if winners:
        first = winners[0]
        print(f"  SONUC: GECEN strateji: {', '.join(winners)}")
        if "--delay-ms" in first:
            base = first.split()[0]
            print(f"         ->  python3 dpi.py --strategy {base} --delay-ms 25")
        else:
            print(f"         ->  python3 dpi.py --strategy {first}")
        print("         (auto mod da bunu kendisi bulur ve learned.json'a yazar)")
        return 0

    print("  SONUC: userspace parcalama bu siteyi acamadi (gelismis DPI).")
    print("         - once:  python3 dpi.py --strategy multi --delay-ms 40")
    print("         - olmazsa GoodbyeDPI/zapret (root + sahte paket) ya da VPN/Tor/Xray gerekir;")
    print("           bu araç ham-soket (sahte paket, TTL) tekniklerini yapmaz.")
    return 1


# ===========================================================================
# 8) CLI
# ===========================================================================
def parse_listen(s):
    s = s.strip()
    if ":" in s:
        host, _, port = s.rpartition(":")
        return (host or "127.0.0.1"), int(port)
    return "127.0.0.1", int(s)


def banner(host, port, args, resolver_desc):
    if args.quiet:
        return
    order = ("auto: " + " -> ".join(DEFAULT_ORDER[:4]) + " ..."
             if args.strategy == "auto" else args.strategy)
    lines = [
        _c("dpi", "36;1") + f"  DPI atlatma proxy'si  v{__version__}",
        f"  dinleniyor : {host}:{port}",
        f"  strateji   : {order}",
        f"  DNS        : {resolver_desc}",
        f"  ogrenme    : {LEARN_FILE}",
        f"  sistem px  : {'AUTO (cikista geri yuklenir)' if args.set_proxy else 'kapali (--no-set-proxy)'}",
        f"  durdur     : Ctrl+C",
    ]
    print("\n".join(lines) + "\n", flush=True)


async def run(args):
    host, port = parse_listen(args.listen)
    loop = asyncio.get_event_loop()

    fd = raise_fd_limit()
    if fd and fd < args.max_conns * 4:
        LOG.debug("acik dosya limiti %s; --max-conns %d'e gore dusuk olabilir", fd, args.max_conns)

    endpoints = args.doh_url or DOH_ENDPOINTS
    resolver = Resolver(endpoints, args.doh, args.doh_strategy, args.timeout, loop)
    learn = LearnStore(LEARN_FILE, fresh=args.fresh)
    proxy = Proxy(resolver, learn, args.strategy, args.delay_ms, args.timeout,
                  args.probe_timeout, args.max_attempts, args.max_conns)

    try:
        server = await asyncio.start_server(proxy.handle, host, port, limit=1 << 20)
    except OSError as e:
        LOG.error("%s:%d dinlenemedi: %s", host, port, e)
        return 1

    rdesc = (f"DoH ({', '.join(urlsplit(x).hostname for x in endpoints)}) - parcali"
             if args.doh else "sistem DNS")
    banner(host, port, args, rdesc)

    proxy_on = False
    if args.set_proxy:
        try:
            svc = SysProxy.enable(host, port, args.service)
            proxy_on = True
            _ok(f"sistem proxy'si {host}:{port} olarak ayarlandi (servis: {svc})")
        except Exception as e:
            _warn(f"sistem proxy'si ayarlanamadi: {e}")
            _warn("elle: Sistem Ayarlari > Ag > Proxy'ler   |   ya da: sudo python3 dpi.py set-proxy")

    def cleanup():
        if proxy_on:
            try:
                SysProxy.restore(silent=True)
                LOG.info("sistem proxy'si geri yuklendi")
            except Exception as e:
                LOG.error("proxy geri yuklenemedi: %s  ->  'python3 dpi.py restore' calistirin", e)
        learn.flush()

    atexit.register(cleanup)

    stop = loop.create_future()
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            loop.add_signal_handler(s, lambda: stop.done() or stop.set_result(None))
        except (NotImplementedError, ValueError):
            pass

    async def housekeeping():
        while True:
            await asyncio.sleep(30)
            learn.flush()

    hk = asyncio.ensure_future(housekeeping())
    if args.doh or True:
        asyncio.ensure_future(self_test(resolver, args.timeout, args.test_host))

    async with server:
        await stop

    hk.cancel()
    st = proxy.stats
    LOG.info("kapatiliyor - %d baglanti, %d blok asildi, %d basarisiz",
             st["conns"], st["bypassed"], st["failed"])
    cleanup()
    atexit.unregister(cleanup)
    return 0


def cmd_set_proxy(args):
    host, port = parse_listen(args.listen)
    try:
        svc = SysProxy.enable(host, port, args.service)
    except Exception as e:
        print(f"hata: {e}", file=sys.stderr)
        print("yonetici gerekebilir:  sudo python3 dpi.py set-proxy", file=sys.stderr)
        return 1
    print(f"sistem proxy'si {host}:{port} olarak ayarlandi (servis: {svc})")
    print("geri almak icin:  python3 dpi.py restore")
    return 0


def cmd_restore(args):
    try:
        SysProxy.restore(silent=False)
    except Exception as e:
        print(f"hata: {e}", file=sys.stderr)
        print("yonetici gerekebilir:  sudo python3 dpi.py restore", file=sys.stderr)
        return 1
    return 0


def cmd_strategies(args):
    print("Stratejiler (auto sirasi: " + " -> ".join(DEFAULT_ORDER) + ")\n")
    for name in DEFAULT_ORDER + [k for k in STRATEGIES if k not in DEFAULT_ORDER]:
        print(f"  {name:<14} {STRATEGIES.get(name, '')}")
    return 0


def cmd_test(args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    endpoints = args.doh_url or DOH_ENDPOINTS
    resolver = Resolver(endpoints, args.doh, args.doh_strategy, args.timeout, loop)
    loop.run_until_complete(self_test(resolver, args.timeout, args.test_host))
    loop.close()
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="dpi", description=f"macOS icin yerel DPI-atlatma proxy'si (v{__version__})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"dpi {__version__}")
    p.add_argument("command", nargs="?", default="run",
                   choices=["run", "set-proxy", "unset-proxy", "restore",
                            "test", "strategies", "diag"],
                   help="run (varsayilan) | set-proxy | restore | test | strategies | diag <site>")
    p.add_argument("target", nargs="?", default=None,
                   help="diag icin alan adi (or: python3 dpi.py diag site.com)")
    p.add_argument("--listen", default="127.0.0.1:8080",
                   help="dinlenecek adres (varsayilan 127.0.0.1:8080)")
    p.add_argument("--strategy", default="auto",
                   help="auto (uyarlanabilir, varsayilan) veya sabit: "
                        + ", ".join(STRATEGIES))
    p.add_argument("--delay-ms", type=int, default=0,
                   help="parcalar arasi gecikme (ms). Bazi DPI'larda 5-40 arasi ise yarar")
    p.add_argument("--max-attempts", type=int, default=8,
                   help="auto modda denenecek strateji sayisi (varsayilan 8)")
    p.add_argument("--probe-timeout", type=float, default=2.5,
                   help="bir strateji 'gecti mi' beklemesi (sn, varsayilan 2.5)")
    p.add_argument("--max-conns", type=int, default=512,
                   help="es zamanli baglanti siniri (varsayilan 512)")
    p.add_argument("--no-set-proxy", dest="set_proxy", action="store_false",
                   help="macOS sistem proxy'sine dokunma")
    p.add_argument("--set-proxy", dest="set_proxy", action="store_true",
                   default=True, help=argparse.SUPPRESS)
    p.add_argument("--service", default=None,
                   help="sistem proxy icin ag servisi adi (or: Wi-Fi)")
    p.add_argument("--no-doh", dest="doh", action="store_false",
                   help="DoH kapali, sistem DNS'i kullanilir")
    p.add_argument("--doh-url", action="append", default=None,
                   help="DoH ucu (birden fazla verilebilir). Varsayilan: Cloudflare + Google")
    p.add_argument("--doh-strategy", default="sni-mid",
                   help="DoH baglantisi icin parcalama stratejisi (varsayilan sni-mid)")
    p.add_argument("--test-host", default="www.wikipedia.org",
                   help="kendi testi icin alan adi")
    p.add_argument("--timeout", type=float, default=10.0, help="baglanti zaman asimi (sn)")
    p.add_argument("--fresh", action="store_true", help="ogrenilmis stratejileri yok say")
    p.add_argument("-q", "--quiet", action="store_true", help="sessiz")
    p.add_argument("-v", "--verbose", action="store_true", help="ayrintili gunlukleme")
    return p


def main():
    args = build_parser().parse_args()
    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format=("%(asctime)s %(message)s" if args.verbose else "%(message)s"),
        datefmt="%H:%M:%S",
    )

    if args.command in ("unset-proxy", "restore"):
        return cmd_restore(args)
    if args.command == "set-proxy":
        return cmd_set_proxy(args)
    if args.command == "strategies":
        return cmd_strategies(args)
    if args.command == "test":
        return cmd_test(args)
    if args.command == "diag":
        return cmd_diag(args)

    try:
        return asyncio.run(run(args)) or 0
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
