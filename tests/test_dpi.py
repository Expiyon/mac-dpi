#!/usr/bin/env python3
"""
Offline unit tests for dpi.py  (stdlib unittest, no network, no system changes).

    python3 -m unittest discover -s tests -v
"""
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# isolate config/backup/learn files into a throwaway dir BEFORE importing dpi
os.environ["DPI_HOME"] = tempfile.mkdtemp(prefix="dpi-test-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dpi  # noqa: E402


def real_client_hello(server_name="test.example.com"):
    """Genuine TLS ClientHello record bytes, produced by the ssl module."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inb, outb, server_hostname=server_name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outb.read()


CH = real_client_hello("test.example.com")


# --------------------------------------------------------------------------- #
class SniParsing(unittest.TestCase):
    def test_finds_sni(self):
        span = dpi.sni_span(CH)
        self.assertIsNotNone(span)
        s, e = span
        self.assertEqual(CH[s:e], b"test.example.com")

    def test_rejects_non_clienthello(self):
        self.assertIsNone(dpi.sni_span(b"\x17\x03\x03\x00\x05hello"))
        self.assertIsNone(dpi.sni_span(b""))
        self.assertIsNone(dpi.sni_span(b"\x16\x03\x01"))

    def test_truncated_is_safe(self):
        for n in range(0, len(CH)):
            dpi.sni_span(CH[:n])  # must never raise


# --------------------------------------------------------------------------- #
class Splitters(unittest.TestCase):
    def test_tcp_split_reassembles(self):
        data = bytes(range(200))
        parts = dpi._tcp_split(data, [10, 50, 199])
        self.assertEqual(b"".join(parts), data)
        self.assertTrue(all(parts))
        self.assertEqual(len(parts), 4)

    def test_tcp_split_ignores_out_of_range(self):
        data = b"abcdef"
        self.assertEqual(dpi._tcp_split(data, [0, 6, 99, -3]), [data])

    def test_record_split_valid_records(self):
        recs = dpi._record_split(CH, [40, 80])
        self.assertEqual(len(recs), 3)
        payload = b""
        for r in recs:
            self.assertEqual(r[0], 0x16)
            self.assertEqual(r[1:3], b"\x03\x01")
            rlen = int.from_bytes(r[3:5], "big")
            self.assertEqual(len(r) - 5, rlen)
            payload += r[5:]
        self.assertEqual(payload, CH[5:])  # handshake bytes unchanged

    def test_record_split_non_tls_passthrough(self):
        self.assertEqual(dpi._record_split(b"nope", [1]), [b"nope"])


# --------------------------------------------------------------------------- #
class Strategies(unittest.TestCase):
    def test_default_order_subset_of_strategies(self):
        for name in dpi.DEFAULT_ORDER:
            self.assertIn(name, dpi.STRATEGIES)

    def test_every_strategy_plans_without_error(self):
        for name in dpi.STRATEGIES:
            ops = dpi.plan(CH, name)
            self.assertTrue(ops)

    def test_pure_split_strategies_preserve_bytes(self):
        for name in ("none", "sni-mid", "sni-1", "split-2", "split-3",
                     "multi", "byte-1", "split-4"):
            self.assertEqual(b"".join(dpi.build_chunks(CH, name)), CH, name)

    def test_oob_strategies_have_sentinel_and_preserve_bytes(self):
        for name in ("oob", "oob-mid"):
            ops = dpi.plan(CH, name)
            self.assertIn(dpi.OOB, ops)
            self.assertEqual(b"".join(dpi.build_chunks(CH, name)), CH, name)

    def test_byte_1_is_one_byte_each(self):
        chunks = dpi.build_chunks(CH, "byte-1")
        self.assertEqual(len(chunks), len(CH))
        self.assertTrue(all(len(c) == 1 for c in chunks))

    def test_record_frag_reassembles_handshake(self):
        for name, n in (("record-frag", 2), ("record-frag-3", 3)):
            recs = dpi.build_chunks(CH, name)
            self.assertEqual(len(recs), n, name)
            self.assertEqual(b"".join(r[5:] for r in recs), CH[5:], name)

    def test_unknown_strategy_is_passthrough(self):
        self.assertEqual(dpi.build_chunks(CH, "does-not-exist"), [CH])


# --------------------------------------------------------------------------- #
class Helpers(unittest.TestCase):
    def test_looks_serverhello(self):
        self.assertTrue(dpi._looks_serverhello(b"\x16\x03\x03\x00\x50"))
        self.assertFalse(dpi._looks_serverhello(b"\x15\x03\x03\x00\x02"))
        self.assertFalse(dpi._looks_serverhello(b""))

    def test_looks_alert(self):
        self.assertTrue(dpi._looks_alert(b"\x15\x03\x03\x00\x02\x02\x28"))
        self.assertFalse(dpi._looks_alert(b"\x16\x03\x03"))

    def test_dechunk(self):
        body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        self.assertEqual(dpi._dechunk(body), b"Wikipedia")

    def test_split_hostport(self):
        self.assertEqual(dpi._split_hostport("example.com:443", 443), ("example.com", 443))
        self.assertEqual(dpi._split_hostport("example.com", 443), ("example.com", 443))
        self.assertEqual(dpi._split_hostport("[2606:4700::1]:8443", 443), ("2606:4700::1", 8443))
        self.assertEqual(dpi._split_hostport("host:bogus", 443), ("host", 443))

    def test_parse_listen(self):
        self.assertEqual(dpi.parse_listen("1.2.3.4:9000"), ("1.2.3.4", 9000))
        self.assertEqual(dpi.parse_listen("8080"), ("127.0.0.1", 8080))
        self.assertEqual(dpi.parse_listen(":8081"), ("127.0.0.1", 8081))

    def test_raise_fd_limit_never_lowers_or_raises(self):
        import resource
        before = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        got = dpi.raise_fd_limit()
        after = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        self.assertGreaterEqual(after, before)
        if got is not None:
            self.assertIsInstance(got, int)


# --------------------------------------------------------------------------- #
class LearnStoreTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(os.environ["DPI_HOME"]) / f"learn-{time.time_ns()}.json"

    def test_record_get_persist_reload(self):
        s = dpi.LearnStore(self.path, fresh=True)
        s.record("a.com", "record-frag")
        s.flush()
        self.assertTrue(self.path.exists())
        s2 = dpi.LearnStore(self.path)
        self.assertEqual(s2.get("a.com"), "record-frag")

    def test_ttl_expiry(self):
        s = dpi.LearnStore(self.path, fresh=True)
        s.record("b.com", "sni-mid")
        s.data["b.com"]["ts"] = int(time.time()) - dpi.LearnStore.TTL - 10
        self.assertIsNone(s.get("b.com"))

    def test_fresh_ignores_existing_file(self):
        self.path.write_text('{"c.com": {"strategy": "byte-1", "ts": %d}}' % int(time.time()))
        self.assertIsNone(dpi.LearnStore(self.path, fresh=True).get("c.com"))
        self.assertEqual(dpi.LearnStore(self.path).get("c.com"), "byte-1")


# --------------------------------------------------------------------------- #
class OrderAndRateLimit(unittest.TestCase):
    def _proxy(self, strategy="auto", max_attempts=8, learned=None):
        p = dpi.Proxy.__new__(dpi.Proxy)
        p.strategy = strategy
        p.max_attempts = max_attempts

        class L:
            def get(self, h):
                return learned
        p.learn = L()
        p._rfail_t = float("-inf")
        p._rfail_n = 0
        return p

    def test_fixed_strategy(self):
        self.assertEqual(self._proxy("record-tcp")._order_for("x"), ["record-tcp"])

    def test_auto_appends_none_and_caps(self):
        order = self._proxy(max_attempts=3)._order_for("x")
        self.assertEqual(order[:3], dpi.DEFAULT_ORDER[:3])
        self.assertEqual(order[-1], "none")

    def test_auto_promotes_learned(self):
        order = self._proxy(learned="byte-1")._order_for("x")
        self.assertEqual(order[0], "byte-1")
        self.assertEqual(order.count("byte-1"), 1)

    def test_resolve_failed_rate_limited(self):
        p = self._proxy()
        with self.assertLogs("dpi", level="INFO") as cm:
            for i in range(6):
                p._resolve_failed(f"h{i}.invalid", "gaierror")
        info = [ln for ln in cm.output if "cozumlenemeyen" in ln]
        self.assertEqual(len(info), 1)               # only one summary for the burst
        p._rfail_t -= 25                              # jump past the window
        with self.assertLogs("dpi", level="INFO") as cm:
            p._resolve_failed("later.invalid", "gaierror")
        self.assertTrue(any("cozumlenemeyen" in ln for ln in cm.output))


# --------------------------------------------------------------------------- #
class DohShortCircuit(unittest.TestCase):
    """A resolver that answers 'no such name' must not be re-tried against
    every other endpoint (that was the bogus-domain slowness)."""

    def test_first_answering_endpoint_wins(self):
        hits = []

        def fake_conn(addr, timeout=None):
            hits.append(addr[0])
            s1, s2 = socket.socketpair()
            s2.close()
            return s1

        def fake_get(tls, host_header, path):
            return b'{"Status": 3, "Answer": []}'   # NXDOMAIN, no records

        orig_conn = socket.create_connection
        orig_get = dpi._http_get_over
        orig_tls = dpi.FragTLS
        socket.create_connection = fake_conn
        dpi._http_get_over = fake_get
        dpi.FragTLS = lambda *a, **k: type("T", (), {"close": lambda s: None})()
        try:
            r = dpi.Resolver(dpi.DOH_ENDPOINTS, True, "sni-mid", 5, None)
            self.assertEqual(r._doh_all("no-such.invalid"), [])
            # A + AAAA against ONE endpoint only, not all four
            self.assertEqual(len(set(hits)), 1, hits)
        finally:
            socket.create_connection = orig_conn
            dpi._http_get_over = orig_get
            dpi.FragTLS = orig_tls

    def test_falls_through_when_endpoint_errors(self):
        hits = []

        def fake_conn(addr, timeout=None):
            hits.append(addr[0])
            raise OSError("boom")

        orig = socket.create_connection
        socket.create_connection = fake_conn
        try:
            r = dpi.Resolver(dpi.DOH_ENDPOINTS, True, "sni-mid", 5, None)
            self.assertEqual(r._doh_all("whatever.example"), [])
            self.assertEqual(len(set(hits)), len(dpi.DOH_ENDPOINTS), hits)
        finally:
            socket.create_connection = orig


# --------------------------------------------------------------------------- #
class SysProxyLogic(unittest.TestCase):
    def test_sanitize_backup_disables_loopback(self):
        st = {"web": {"enabled": True, "server": "127.0.0.1", "port": "8080"},
              "secure": {"enabled": True, "server": "192.168.1.9", "port": "3128"}}
        out = dpi.SysProxy._sanitize_backup(dict(st, service="X"))
        self.assertFalse(out["web"]["enabled"])
        self.assertEqual(out["web"]["server"], "")
        self.assertTrue(out["secure"]["enabled"])          # real proxy left intact
        self.assertEqual(out["secure"]["server"], "192.168.1.9")

    def test_enable_then_restore_roundtrip_stubbed(self):
        calls = []
        # a machine that already had a corporate proxy configured
        state = {
            "-getwebproxy": "Enabled: Yes\nServer: 10.0.0.9\nPort: 3128\n",
            "-getsecurewebproxy": "Enabled: No\nServer: \nPort: 0\n",
            "-getproxybypassdomains": "*.corp.local\n",
        }

        class R:
            def __init__(self, out=""):
                self.stdout = out

        def fake_ns(*args, check=True):
            args = list(args)
            calls.append(args)
            flag = args[0]
            if flag in state:
                return R(state[flag])
            if flag == "-setwebproxy":
                state["-getwebproxy"] = f"Enabled: Yes\nServer: {args[2]}\nPort: {args[3]}\n"
            elif flag == "-setsecurewebproxy":
                state["-getsecurewebproxy"] = f"Enabled: Yes\nServer: {args[2]}\nPort: {args[3]}\n"
            elif flag == "-setwebproxystate":
                cur = state["-getwebproxy"]
                yn = "Yes" if args[2] == "on" else "No"
                state["-getwebproxy"] = cur.replace("Enabled: Yes", f"Enabled: {yn}").replace("Enabled: No", f"Enabled: {yn}")
            elif flag == "-setsecurewebproxystate":
                cur = state["-getsecurewebproxy"]
                yn = "Yes" if args[2] == "on" else "No"
                state["-getsecurewebproxy"] = cur.replace("Enabled: Yes", f"Enabled: {yn}").replace("Enabled: No", f"Enabled: {yn}")
            elif flag == "-setproxybypassdomains":
                state["-getproxybypassdomains"] = "\n".join(args[2:]) + "\n"
            return R("")

        orig_ns = dpi.SysProxy._ns
        orig_ps = dpi.SysProxy.primary_service
        dpi.SysProxy._ns = staticmethod(fake_ns)
        dpi.SysProxy.primary_service = classmethod(lambda cls: "TestNet")
        try:
            if dpi.BACKUP_FILE.exists():
                dpi.BACKUP_FILE.unlink()
            svc = dpi.SysProxy.enable("127.0.0.1", 8080)
            self.assertEqual(svc, "TestNet")
            self.assertTrue(dpi.BACKUP_FILE.exists())
            self.assertIn("Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\n", state["-getwebproxy"])

            dpi.SysProxy.restore(silent=True)
            self.assertFalse(dpi.BACKUP_FILE.exists())
            self.assertIn("Server: 10.0.0.9", state["-getwebproxy"])
            self.assertIn("Enabled: Yes", state["-getwebproxy"])
            self.assertIn("*.corp.local", state["-getproxybypassdomains"])
        finally:
            dpi.SysProxy._ns = orig_ns
            dpi.SysProxy.primary_service = orig_ps


# --------------------------------------------------------------------------- #
class FragTLSLeak(unittest.TestCase):
    """A failed handshake must not leak the socket fd (the Errno 24 bug)."""

    @staticmethod
    def _open_fds():
        for p in ("/proc/self/fd", "/dev/fd"):
            if os.path.isdir(p):
                return len(os.listdir(p))
        return -1

    def test_no_fd_leak_on_failed_handshake(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(16)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def accept_and_drop():
            srv.settimeout(0.5)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                    c.close()          # no TLS -> handshake fails
                except (OSError, socket.timeout):
                    pass

        t = threading.Thread(target=accept_and_drop, daemon=True)
        t.start()
        base = self._open_fds()
        if base < 0:
            self.skipTest("no /proc/self/fd or /dev/fd")
        for _ in range(40):
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                dpi.FragTLS(raw, "x", lambda d: [d], 0.5, verify=False)
            except Exception:
                pass
        after = self._open_fds()
        stop.set()
        srv.close()
        self.assertLessEqual(after - base, 2, f"fd delta {after - base}")


# --------------------------------------------------------------------------- #
class Cli(unittest.TestCase):
    def test_subcommands_parse(self):
        p = dpi.build_parser()
        self.assertEqual(p.parse_args([]).command, "run")
        self.assertEqual(p.parse_args(["diag", "x.com"]).target, "x.com")
        self.assertEqual(p.parse_args(["run", "--strategy", "record-frag"]).strategy, "record-frag")
        self.assertEqual(p.parse_args(["--max-conns", "64"]).max_conns, 64)
        for c in ("run", "set-proxy", "unset-proxy", "restore", "test", "strategies", "diag"):
            self.assertEqual(p.parse_args([c]).command, c)

    def test_bad_command_exits(self):
        with self.assertRaises(SystemExit):
            dpi.build_parser().parse_args(["frobnicate"])

    def test_version_exits(self):
        with self.assertRaises(SystemExit):
            dpi.build_parser().parse_args(["--version"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
