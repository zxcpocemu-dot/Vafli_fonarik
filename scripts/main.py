#!/usr/bin/env python3
"""Freedom-V2Ray filter - VLESS + SS, Europe+nearby, robust URL test, max 300."""
import base64, json, os, random, socket, subprocess, sys, tempfile, threading, time, zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, unquote
import requests

FUNDAMENTAL_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt"
MAX_SERVERS = 300
TEST_URL = "http://connect.rom.miui.com/generate_204"
TEST_TIMEOUT = 15.0      # увеличен с 8 до 15 сек - слабые серверы успевают ответить
STARTUP_TIMEOUT = 6.0    # увеличен с 3 до 6 сек - xray успевает подняться
PARALLEL = 8             # уменьшен с 10 до 8 - меньше потерянных ответов
MAX_RETRY = 2            # количество попыток для провалившихся
GEO_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,status"
OUTPUT_PATH = Path("output/mix_sub.txt")

XRAY_BIN = Path("/tmp/xray-core")
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

EUROPE = {"AD","AL","AT","BA","BE","BG","BY","CH","CY","CZ","DE","DK","EE","ES","FI","FO","FR","GB","GG","GI","GR","HR","HU","IE","IM","IS","IT","JE","LI","LT","LU","LV","MC","MD","ME","MK","MT","NL","NO","PL","PT","RO","RS","SE","SI","SK","SM","UA","VA","AX","XK"}
NEARBY = {"TR","GE","AM","AZ","KZ","IL","AE","JO","LB","QA","KW","BH","OM","SA"}
ALLOWED = (EUROPE | NEARBY) - {"RU"}

ADJ = ["quiet","swift","bright","calm","bold","fancy","lucky","neat","proud","warm","silent","golden","silver","wild","free","azure","noble","prime","vivid","pure"]
NOUN = ["meadow","river","star","forest","cloud","stone","wave","hill","moon","sun","field","lake","peak","sky","wind","oak","pine","sage","vale","bay"]

def country_flag(cc):
    if not cc or len(cc) != 2: return ""
    try:
        return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + chr(0x1F1E6 + ord(cc[1].upper()) - 65)
    except Exception:
        return ""

def gen_name(cc):
    base = f"{random.choice(ADJ)}-{random.choice(NOUN)}-{random.randint(100,999)}"
    return f"{country_flag(cc)} {base} 🤩".strip()

def b64_pad(s):
    return s + "=" * (-len(s) % 4)

def parse_vless(link):
    rest = link[8:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    query = ""
    if "?" in rest: rest, query = rest.split("?", 1)
    if "@" not in rest: return None
    userinfo, hostport = rest.rsplit("@", 1)
    hostport = hostport.rstrip("/")
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    try: port = int(port)
    except Exception: return None
    params = {}
    if query:
        for p in query.split("&"):
            if not p: continue
            if "=" in p:
                k, v = p.split("=", 1); params[k] = unquote(v)
            else:
                params[p] = ""
    return {"type":"vless","host":host,"port":port,"raw":link,
            "uuid":unquote(userinfo),"params":params}

def parse_ss(link):
    rest = link[5:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "@" in rest:
        userinfo_b64, hostport = rest.rsplit("@", 1)
        hostport = hostport.rstrip("/")
        if ":" not in hostport: return None
        host, port = hostport.rsplit(":", 1)
        try: port = int(port)
        except Exception: return None
        try: decoded = base64.b64decode(b64_pad(userinfo_b64)).decode("utf-8", errors="ignore")
        except Exception:
            decoded = unquote(userinfo_b64)
        if ":" not in decoded: return None
        method, password = decoded.split(":", 1)
        return {"type":"ss","host":host,"port":port,"raw":link,"method":method,"password":password}
    try: decoded = base64.b64decode(b64_pad(rest)).decode("utf-8", errors="ignore")
    except Exception: return None
    if "@" not in decoded: return None
    userinfo, hostport = decoded.rsplit("@", 1)
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    try: port = int(port)
    except Exception: return None
    if ":" not in userinfo: return None
    method, password = userinfo.split(":", 1)
    return {"type":"ss","host":host,"port":port,"raw":link,"method":method,"password":password}

def parse_server(link):
    link = link.strip()
    if link.startswith("vless://"): return parse_vless(link)
    if link.startswith("ss://"):    return parse_ss(link)
    return None

def build_outbound(s):
    if s["type"] == "vless":
        p = s["params"]
        sec = (p.get("security","none") or "none").lower()
        net = (p.get("type","tcp") or "tcp").lower()
        sni = p.get("sni") or p.get("host") or s["host"]
        fp = p.get("fp","") or "chrome"
        pbk = p.get("pbk","") or ""
        sid = p.get("sid","") or ""
        spx = p.get("spx","") or "/"
        flow = p.get("flow","") or ""
        path = p.get("path","/") or "/"
        host_header = p.get("host","") or ""
        svc = p.get("serviceName","") or ""
        alpn = p.get("alpn","") or ""
        stream = {"network": net, "security": sec}
        if sec == "tls":
            ts = {"serverName": sni, "fingerprint": fp}
            if alpn: ts["alpn"] = [a for a in alpn.split(",") if a]
            stream["tlsSettings"] = ts
        elif sec == "reality":
            stream["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp,
                "publicKey": pbk,
                "shortId": sid,
                "spiderX": spx
            }
        if net == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host_header or sni}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": svc or path}
        elif net in ("h2","http"):
            stream["httpSettings"] = {"path": path, "host": [host_header or sni]}
        elif net == "tcp" and p.get("headerType") == "http":
            stream["tcpSettings"] = {"header": {"type":"http","request":{"headers":{"Host":[host_header or sni]}}}}
        user = {"id": s["uuid"], "encryption": "none"}
        if flow: user["flow"] = flow
        return {"protocol":"vless","settings":{"vnext":[{"address":s["host"],"port":s["port"],"users":[user]}]},"streamSettings":stream}
    if s["type"] == "ss":
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":s["host"],"port":s["port"],"method":s["method"],"password":s["password"]}]}}
    return None

def ensure_xray():
    if XRAY_BIN.exists(): return XRAY_BIN
    print("Downloading Xray...")
    r = requests.get(XRAY_URL, timeout=120); r.raise_for_status()
    with zipfile.ZipFile(BytesIO(r.content)) as z:
        XRAY_BIN.write_bytes(z.read("xray"))
    XRAY_BIN.chmod(0o755)
    print(f"Xray ready: {XRAY_BIN}")
    return XRAY_BIN

_port_lock = threading.Lock()
_port_next = [20000]

def url_test_once(s, xray_bin):
    """Single URL test attempt. Returns latency in ms or None."""
    outbound = build_outbound(s)
    if not outbound: return None
    with _port_lock:
        port = _port_next[0]; _port_next[0] += 1
        if _port_next[0] > 60000: _port_next[0] = 20000
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                      "settings": {"udp": False, "auth": "noauth"}}],
        "outbounds": [outbound]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(cfg, f); cfg_path = f.name
    proc = None
    try:
        proc = subprocess.Popen([str(xray_bin), "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + STARTUP_TIMEOUT
        started = False
        while time.time() < deadline:
            if proc.poll() is not None:
                return None
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                sock.close()
                started = True; break
            except Exception:
                time.sleep(0.08)
        if not started:
            return None
        proxies = {"http": f"socks5h://127.0.0.1:{port}",
                   "https": f"socks5h://127.0.0.1:{port}"}
        start = time.perf_counter()
        try:
            r = requests.get(TEST_URL, proxies=proxies, timeout=TEST_TIMEOUT)
            lat = (time.perf_counter() - start) * 1000
            return lat if r.status_code == 204 else None
        except Exception:
            return None
    finally:
        if proc:
            try: proc.terminate()
            except Exception: pass
            try: proc.wait(timeout=1)
            except Exception:
                try: proc.kill()
                except Exception: pass
        try: os.unlink(cfg_path)
        except Exception: pass

def url_test(s, xray_bin):
    """Try URL test up to MAX_RETRY times, return best latency."""
    best = None
    for attempt in range(MAX_RETRY):
        lat = url_test_once(s, xray_bin)
        if lat is not None:
            if best is None or lat < best:
                best = lat
            break
    return best

def geo_lookup(hosts):
    result = {}; ip_to_host = {}
    for h in hosts:
        try: ip = socket.gethostbyname(h)
        except Exception: continue
        ip_to_host[ip] = h
    ips = list(ip_to_host.keys())
    for i in range(0, len(ips), 100):
        chunk = ips[i:i+100]
        try:
            r = requests.post(GEO_BATCH_URL, json=[{"query": ip} for ip in chunk], timeout=30)
            r.raise_for_status()
            for e in r.json():
                if e.get("status") == "success":
                    result[ip_to_host[e["query"]]] = e.get("countryCode")
        except Exception as ex:
            print(f"  geo err: {ex}", file=sys.stderr)
        time.sleep(1)
    return result

def randomize_name(s):
    name = gen_name(s.get("cc",""))
    base = s["raw"].split("#", 1)[0]
    return f"{base}#{quote(name)}"

def main():
    print(f"=== Freedom filter (VLESS+SS, robust URL test, max {MAX_SERVERS}) ===")
    print(f"Settings: TEST_TIMEOUT={TEST_TIMEOUT}s, STARTUP_TIMEOUT={STARTUP_TIMEOUT}s, PARALLEL={PARALLEL}, MAX_RETRY={MAX_RETRY}")
    r = requests.get(FUNDAMENTAL_URL, timeout=30); r.raise_for_status()
    try:
        decoded = base64.b64decode(b64_pad(r.text.strip())).decode("utf-8", errors="ignore")
    except Exception:
        decoded = r.text
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    print(f"Total lines: {len(lines)}")

    counts = {"vless": 0, "ss": 0, "skipped": 0}
    servers = []
    for l in lines:
        if l.startswith("vless://"): counts["vless"] += 1
        elif l.startswith("ss://"):  counts["ss"] += 1
        else: counts["skipped"] += 1; continue
        s = parse_server(l)
        if s: servers.append(s)
    print(f"VLESS: {counts['vless']}, Shadowsocks: {counts['ss']}, skipped: {counts['skipped']}")
    print(f"Parsed: {len(servers)}")
    if not servers: return

    print("Geo lookup...")
    geo = geo_lookup([s["host"] for s in servers])
    pool = []
    for s in servers:
        cc = geo.get(s["host"])
        if cc and cc in ALLOWED:
            s["cc"] = cc; pool.append(s)
    print(f"Europe + nearby (excl. RU): {len(pool)}")
    if not pool:
        print("Empty, keeping previous output."); return

    xray = ensure_xray()
    print(f"URL test via {TEST_URL} (parallel {PARALLEL}, retries {MAX_RETRY})...")
    print(f"Estimated time: ~{len(pool) * MAX_RETRY * TEST_TIMEOUT / PARALLEL / 60:.0f} min worst case")
    alive = []
    with ThreadPoolExecutor(max_workers=PARALLEL) as ex:
        futs = {ex.submit(url_test, s, xray): s for s in pool}
        done = 0
        t_start = time.time()
        for fut in as_completed(futs):
            s = futs[fut]
            try: lat = fut.result()
            except Exception: lat = None
            if lat is not None:
                s["ping"] = lat; alive.append(s)
            done += 1
            if done % 20 == 0:
                elapsed = time.time() - t_start
                eta = elapsed / done * (len(pool) - done)
                print(f"  progress {done}/{len(pool)}, alive: {len(alive)}, ETA {eta:.0f}s")
    print(f"Alive (URL test passed): {len(alive)}")
    if not alive:
        print("No working servers, keeping previous output."); return

    alive.sort(key=lambda s: s["ping"])
    final = alive[:MAX_SERVERS]
    vless_n = sum(1 for s in final if s["type"]=="vless")
    ss_n = sum(1 for s in final if s["type"]=="ss")
    print(f"Selected: {len(final)} servers (VLESS: {vless_n}, SS: {ss_n})")

    out_lines = [randomize_name(s) for s in final]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode("\n".join(out_lines).encode("utf-8")).decode("ascii")
    OUTPUT_PATH.write_text(encoded, encoding="utf-8")
    print(f"Written {OUTPUT_PATH} ({len(out_lines)} servers)")

if __name__ == "__main__":
    main()