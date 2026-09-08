#!/bin/bash
# Canli entegrasyon testleri (ag gerektirir, sistem proxy'sine DOKUNMAZ).
#   ./tests/integration.sh
# CI'da calismaz; elle / gelistirici makinesinde.
set -u
cd "$(dirname "$0")/.."

PORT=${PORT:-8899}
PROXY="http://127.0.0.1:$PORT"
TMP=$(mktemp -d)
export DPI_HOME="$TMP/home"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

curl_code() { curl -x "$PROXY" -sS -o /dev/null -w '%{http_code}' --max-time 25 "$1" 2>/dev/null; }

PID=""
start() {
  # herhangi bir kalinti dinleyiciyi temizle
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | xargs -r kill -9 2>/dev/null
  python3 dpi.py run --no-set-proxy --listen "127.0.0.1:$PORT" "$@" >"$TMP/log" 2>&1 & PID=$!
  sleep 3
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "  !! proxy baslamadi:"; sed 's/^/     /' "$TMP/log"
  fi
}
stop()  { [ -n "$PID" ] && kill -INT "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }
cleanup_all() { [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup_all EXIT

# ---------------------------------------------------------------- CLI surface
hdr "CLI"
python3 dpi.py --version            >/dev/null 2>&1 && ok "--version"            || bad "--version"
python3 dpi.py strategies           >/dev/null 2>&1 && ok "strategies"           || bad "strategies"
python3 dpi.py -h                   >/dev/null 2>&1 && ok "-h"                    || bad "-h"
python3 -m py_compile dpi.py        2>&1            && ok "py_compile"            || bad "py_compile"

# ---------------------------------------------------------------- self-test
hdr "self-test"
python3 dpi.py test 2>&1 | grep -q "gecti" && ok "dpi.py test" || bad "dpi.py test"

# ---------------------------------------------------------------- DoH endpoints
hdr "DoH endpoints"
python3 - <<'PY' && ok "each DoH endpoint resolves" || bad "DoH endpoint"
import dpi, sys
bad=0
for ep in dpi.DOH_ENDPOINTS:
    r=dpi.Resolver([ep],True,"sni-mid",8,None)
    try:
        ips=r._doh_all("www.wikipedia.org")
        print(f"  {ep:<32} {ips[:2]}")
        bad += 0 if ips else 1
    except Exception as e:
        print("  ERR",ep,e); bad+=1
sys.exit(1 if bad else 0)
PY

# ---------------------------------------------------------------- auto proxy
hdr "auto mode - HTTPS matrix"
start
for u in https://example.com https://www.google.com https://www.cloudflare.com \
         https://github.com https://www.wikipedia.org https://discord.com \
         https://www.youtube.com https://open.spotify.com; do
  c=$(curl_code "$u")
  [ "$c" = 200 ] && ok "$u -> 200" || bad "$u -> $c"
done
c=$(curl_code http://example.com); [ "$c" = 200 ] && ok "plain HTTP -> 200" || bad "plain HTTP -> $c"
# a failed CONNECT tunnel puts the code in %{http_connect}, not %{http_code}
c=$(curl -x "$PROXY" -sS -o /dev/null -w '%{http_connect}' --max-time 25 https://nonexistent-zzqq-9f8a.invalid 2>/dev/null)
[ "$c" = 502 ] && ok "bogus domain -> 502 (fast)" || bad "bogus -> http_connect=$c"
grep -q "learned.json" "$TMP/log" && ok "banner shows learn path" || bad "banner"
stop
[ -f "$DPI_HOME/learned.json" ] && ok "learned.json written" || bad "learned.json missing"

# ---------------------------------------------------------------- learned reuse
hdr "learned strategy reused (fast path)"
start
t=$( { /usr/bin/time -p curl -x "$PROXY" -sS -o /dev/null --max-time 20 https://discord.com; } 2>&1 | awk '/real/{print $2}')
awk -v t="$t" 'BEGIN{exit !(t<3)}' && ok "cached discord.com in ${t}s (<3s)" || bad "cached discord.com slow: ${t}s"
stop

# ---------------------------------------------------------------- forced strategies
hdr "forced --strategy"
for s in record-frag record-tcp record-frag-3 sni-mid split-2 multi oob-mid byte-1 none; do
  start --strategy "$s"
  c=$(curl_code https://www.cloudflare.com)
  [ "$c" = 200 ] && ok "--strategy $s -> 200" || bad "--strategy $s -> $c"
  stop
done

# ---------------------------------------------------------------- adaptive fallback
hdr "adaptive fallback (synthetic RST-after-ClientHello)"
python3 - "$TMP" <<'PY'
import socket, struct, threading, sys, time, json, asyncio, os
sys.path.insert(0, os.getcwd())
import dpi
# fake DPI upstream: 1st strategy dropped, 2nd returns ServerHello
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",0)); srv.listen(16); port=srv.getsockname()[1]
n=[0]
def serve():
    while True:
        try: c,_=srv.accept()
        except OSError: return
        i=n[0]; n[0]+=1
        try:
            c.recv(9000)
            if i==0:
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii",1,0)); c.close()
            else:
                c.sendall(bytes([0x16,0x03,0x03,0,0x2a])+b"x"*42); time.sleep(0.2); c.close()
        except OSError:
            try: c.close()
            except OSError: pass
threading.Thread(target=serve,daemon=True).start()

class R:
    async def resolve(self,h): return ["127.0.0.1"]
learn=dpi.LearnStore(dpi.Path(sys.argv[1])/"l.json", fresh=True)
p=dpi.Proxy(R(), learn, "auto", 0, 3, 1.0, 8)
async def main():
    class FR:
        def __init__(s,d): s.d=d; s.done=False
        async def read(s,n=-1):
            if s.done:
                await asyncio.sleep(5); return b""
            s.done=True; return s.d
    class FW:
        def __init__(s): s.buf=b""
        def write(s,d): s.buf+=d
        async def drain(s): pass
        def close(s): pass
        def get_extra_info(s,k): return None
    ch=bytes([0x16,0x03,0x01,0,0x50])+b"\x01"+b"\0"*0x4c+b"blocked.example"
    cr,cw=FR(ch),FW()
    p._relay=lambda *a: asyncio.sleep(0)
    # resolver returns 127.0.0.1; the fake server's port goes in the CONNECT target
    # so _prime (raw sockets) dials it directly -- no asyncio internals patched.
    await p._connect(cr, cw, f"blocked.example:{port}", b"")
    body = cw.buf[len(b"HTTP/1.1 200 Connection established\r\n\r\n"):]
    assert cw.buf.startswith(b"HTTP/1.1 200"), cw.buf[:40]
    assert body[:1] == b"\x16", "no ServerHello forwarded after fallback"
    assert learn.get("blocked.example") is not None, "did not learn a strategy"
    assert p.stats["bypassed"] == 1, p.stats
    print("  fallback advanced, learned:", learn.get("blocked.example"), "stats:", p.stats)
asyncio.run(main())
PY
[ $? -eq 0 ] && ok "adaptive fallback + learn" || bad "adaptive fallback"

# ---------------------------------------------------------------- concurrency
hdr "concurrency"
start --max-conns 5
res=$(seq 40 | xargs -P40 -I{} curl -x "$PROXY" -sS -o /dev/null -w '%{http_code}\n' --max-time 30 https://example.com | sort | uniq -c | tr -s ' ')
echo "  $res"
echo "$res" | grep -q "40 200" && ok "40 parallel w/ max-conns 5 -> all 200 (queued)" || bad "concurrency: $res"
stop

# ---------------------------------------------------------------- fd stability
hdr "fd leak under load"
start
fd_count() { lsof -p "$1" 2>/dev/null | wc -l | tr -d ' '; }
before=$(fd_count "$PID")
for i in $(seq 150); do curl -x "$PROXY" -s -o /dev/null --max-time 15 https://example.com; done
sleep 2
after=$(fd_count "$PID")
echo "  fd before=$before after=$after"
awk -v b="$before" -v a="$after" 'BEGIN{exit !(a-b < 40)}' && ok "no fd leak over 150 conns (delta $((after-before)))" || bad "fd grew $((after-before))"
stop

# ---------------------------------------------------------------- --no-doh
hdr "--no-doh (system DNS)"
start --no-doh
c=$(curl_code https://example.com); [ "$c" = 200 ] && ok "--no-doh -> 200" || bad "--no-doh -> $c"
stop

# ---------------------------------------------------------------- graceful shutdown
hdr "graceful shutdown"
start
curl_code https://example.com >/dev/null
kill -INT "$PID"; wait "$PID" 2>/dev/null; PID=""
grep -q "kapatiliyor" "$TMP/log" && ok "SIGINT -> clean shutdown line" || bad "no shutdown line"

# ---------------------------------------------------------------- diag
hdr "diag"
python3 dpi.py diag example.com 2>&1 | grep -q "SNI filtresi yok\|GECEN strateji\|SONUC" && ok "diag example.com verdict" || bad "diag example.com"
python3 dpi.py diag discord.com 2>&1 | grep -q "GECEN strateji\|SONUC" && ok "diag discord.com verdict" || bad "diag discord.com"
python3 dpi.py diag 192.0.2.1 2>&1 | grep -q "cozulemedi\|SYN'e cevap YOK\|SONUC" && ok "diag null-route/bogus verdict" || bad "diag null-route"

# ---------------------------------------------------------------- shell scripts
hdr "shell scripts"
for f in dpi.command install-service.sh uninstall-service.sh DPI.app/Contents/MacOS/dpi-launcher; do
  bash -n "$f" 2>&1 && ok "bash -n $f" || bad "bash -n $f"
done

# ---------------------------------------------------------------- py3.8 static
hdr "python 3.8 compat (static)"
if grep -nE ':\s*(list|dict|tuple|set)\[|->\s*(list|dict|tuple|set)\[|[^|]\|\s*None\b|:=|^\s*match .+:' dpi.py; then
  bad "3.8-incompatible syntax found"
else
  ok "no 3.9+/3.10+ syntax"
fi

# ---------------------------------------------------------------- summary
printf '\n===================\n  PASS %d   FAIL %d\n===================\n' "$PASS" "$FAIL"
rm -rf "$TMP"
[ "$FAIL" -eq 0 ]
