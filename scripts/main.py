#!/usr/bin/env python3
"""Freedom-V2Ray filter v4: OS-aware, real xray test, EU-only, top-100, flags + emoji."""
import base64, json, os, platform, random, socket, subprocess, sys, tempfile, threading, time, zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
from pathlib import Path
from urllib.parse import quote, unquote
import requests

IS_WINDOWS = platform.system() == "Windows"
FUNDAMENTAL_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt"
MAX_PING_MS = int(os.environ.get("MAX_PING_MS", "300"))
MAX_SERVERS = 100
TEST_TIMEOUT = 5.0
PARALLEL = 15
GEO_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,status"
OUTPUT_PATH = Path("output/mix_sub.txt")

if IS_WINDOWS:
    XRAY_DIR = Path("scripts/bin")
    XRAY_BIN = XRAY_DIR / "xray.exe"
    XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
    XRAY_ARC = "xray.exe"
else:
    XRAY_DIR = Path("/tmp")
    XRAY_BIN = XRAY_DIR / "xray-core"
    XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    XRAY_ARC = "xray"

EUROPE = {"AD","AL","AT","BA","BE","BG","BY","CH","CY","CZ","DE","DK","EE","ES","FI","FO","FR","GB","GG","GI","GR","HR","HU","IE","IM","IS","IT","JE","LI","LT","LU","LV","MC","MD","ME","MK","MT","NL","NO","PL","PT","RO","RS","SE","SI","SK","SM","UA","VA","AX","XK"}
ALLOWED = EUROPE - {"RU"}

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
    flag = country_flag(cc)
    return f"{flag} {base} 🤩".strip()

def b64_pad(s):
    return s + "=" * (-len(s) % 4)

def parse_vmess(link):
    try:
        data = json.loads(base64.b64decode(b64_pad(link[8:])).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    host = data.get("add"); port = data.get("port")
    if not host or not port: return None
    try: port = int(port)
    except Exception: return None
    uuid = data.get("id")
    if not uuid: return None
    try: aid = int(data.get("aid", 0))
    except Exception: aid = 0
    return {"type":"vmess","host":host,"port":port,"raw":link,"uuid":uuid,"aid":aid,
            "scy": data.get("scy","auto") or "auto",
            "network": (data.get("net","tcp") or "tcp").lower(),
            "tls_sec": (data.get("tls","") or "").lower(),
            "sni": data.get("sni") or data.get("host") or host,
            "host_header": data.get("host","") or "",
            "path": data.get("path","/") or "/",
            "fp": data.get("fp","") or "",
            "alpn": data.get("alpn","") or "",
            "header_type": (data.get("type","none") or "none").lower()}

def parse_url_like(link, scheme):
    rest = link[len(scheme)+3:]
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
    return {"type":scheme,"host":host,"port":port,"raw":link,"userinfo":unquote(userinfo),"params":params}

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
        except Exception: return None
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
    if link.startswith("vmess://"):  return parse_vmess(link)
    if link.startswith("vless://"):  return parse_url_like(link, "vless")
    if link.startswith("trojan://"): return parse_url_like(link, "trojan")
    if link.startswith("ss://"):     return parse_ss(link)
    return None

def ensure_xray():
    if XRAY_BIN.exists(): return XRAY_BIN
    XRAY_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading Xray for {platform.system()}...")
    r = requests.get(XRAY_URL, timeout=120); r.raise_for_status()
    with zipfile.ZipFile(BytesIO(r.content)) as z:
        XRAY_BIN.write_bytes(z.read(XRAY_ARC))
    if not IS_WINDOWS:
        XRAY_BIN.chmod(0o755)
    print(f"Xray ready: {XRAY_BIN}")
    return XRAY_BIN

def build_outbound(s):
    t = s["type"]
    if t == "vmess":
        net = s["network"]; sec = s["tls_sec"]
        stream = {"network": net}
        if sec in ("tls", "reality"):
            stream["security"] = sec
            ts = {"serverName": s["sni"]}
            if s["fp"]: ts["fingerprint"] = s["fp"]
            if s["alpn"]: ts["alpn"] = [a for a in s["alpn"].split(",") if a]
            stream["tlsSettings"] = ts
        if net == "ws":
            stream["wsSettings"] = {"path": s["path"], "headers": {"Host": s["host_header"] or s["sni"]}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": s["path"] or ""}
        elif net == "h2":
            stream["httpSettings"] = {"path": s["path"], "host": [s["host_header"] or s["sni"]]}
        elif net == "tcp" and s["header_type"] == "http":
            stream["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": [s["host_header"] or s["sni"]]}}}}
        return {"protocol":"vmess","settings":{"vnext":[{"address":s["host"],"port":s["port"],"users":[{"id":s["uuid"],"alterId":s["aid"],"security":s["scy"]}]}]},"streamSettings":stream}
    if t == "vless":
        p = s["params"]
        sec = (p.get("security","none") or "none").lower()
        net = (p.get("type","tcp") or "tcp").lower()
        sni = p.get("sni") or s["host"]
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
            stream["realitySettings"] = {"serverName": sni, "fingerprint": fp, "publicKey": pbk, "shortId": sid, "spiderX": spx}
        if net == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host_header or sni}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": svc or path}
        elif net in ("h2", "http"):
            stream["httpSettings"] = {"path": path, "host": [host_header or sni]}
        elif net == "tcp" and p.get("headerType") == "http":
            stream["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": [host_header or sni]}}}}
        user = {"id": s["userinfo"], "encryption": "none"}
        if flow: user["flow"] = flow
        return {"protocol":"vless","settings":{"vnext":[{"address":s["host"],"port":s["port"],"users":[user]}]},"streamSettings":stream}
    if t == "trojan":
        p = s["params"]
        sec = (p.get("security","tls") or "tls").lower()
        net = (p.get("type","tcp") or "tcp").lower()
        sni = p.get("sni") or s["host"]
        fp = p.get("fp","") or "chrome"
        path = p.get("path","/") or "/"
        host_header = p.get("host","") or ""
        stream = {"network": net, "security": sec}
        if sec == "tls":
            stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp}
        if net == "ws":
            stream["wsSettings"] = {"path": path, "headers": {"Host": host_header or sni}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": path}
        return {"protocol":"trojan","settings":{"servers":[{"address":s["host"],"port":s["port"],"password":s["userinfo"]}]},"streamSettings":stream}
    if t == "ss":
        return {"protocol":"shadowsocks","settings":{"servers":[{"address":s["host"],"port":s["port"],"method":s["method"],"password":s["password"]}]}}
    return None

_port_lock = threading.Lock()
_port_next = [20000]

def real_test(s, xray_bin):
    outbound = build_outbound(s)
    if not outbound: return None
    with _port_lock:
        port = _port_next[0]; _port_next[0] += 1
    cfg = {"log":{"loglevel":"error"},
           "inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":False,"auth":"noauth"}}],
           "outbounds":[outbound]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(cfg, f); cfg_path = f.name
    proc = None
    try:
        creationflags = 0x08000000 if IS_WINDOWS else 0
        proc = subprocess.Popen([str(xray_bin), "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=creationflags)
        deadline = time.time() + 3
        started = False
        while time.time() < deadline:
            if proc.poll() is not None: return None
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.2); sock.close()
                started = True; break
            except Exception:
                time.sleep(0.05)
        if not started: return None
        start = time.perf_counter()
        try:
            r = requests.get("http://cp.cloudflare.com/generate_204",
                             proxies={"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"},
                             timeout=TEST_TIMEOUT)
            lat = (time.perf_counter() - start) * 1000
            return lat if r.status_code == 204 else None
        except Exception:
            return None
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except Exception: proc.kill()
        try: os.unlink(cfg_path)
        except Exception: pass

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
    if s["type"] == "vmess":
        try:
            data = json.loads(base64.b64decode(b64_pad(s["raw"][8:])).decode("utf-8", errors="ignore"))
        except Exception:
            return s["raw"]
        data["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(data, separators=(",",":"), ensure_ascii=False).encode()).decode()
    base = s["raw"].split("#", 1)[0]
    return f"{base}#{quote(name)}"

def main():
    print(f"=== Filter v4 ({platform.system()}) ===")
    print(f"MAX_PING_MS = {MAX_PING_MS}")
    r = requests.get(FUNDAMENTAL_URL, timeout=30); r.raise_for_status()
    try:
        decoded = base64.b64decode(b64_pad(r.text.strip())).decode("utf-8", errors="ignore")
    except Exception:
        decoded = r.text
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    print(f"Total lines: {len(lines)}")
    servers = [s for s in (parse_server(l) for l in lines) if s]
    print(f"Parsed: {len(servers)}")
    if not servers: return
    print("Geo lookup...")
    geo = geo_lookup([s["host"] for s in servers])
    eu = []
    for s in servers:
        cc = geo.get(s["host"])
        if cc and cc in ALLOWED:
            s["cc"] = cc; eu.append(s)
    print(f"Europe (excl. RU): {len(eu)}")
    if not eu: return
    xray = ensure_xray()
    print(f"Real xray test, parallel={PARALLEL}, timeout={TEST_TIMEOUT}s, max={MAX_PING_MS}ms")
    working = []
    with ThreadPoolExecutor(max_workers=PARALLEL) as ex:
        futs = {ex.submit(real_test, s, xray): s for s in eu}
        done = 0
        for fut in as_completed(futs):
            s = futs[fut]
            try: lat = fut.result()
            except Exception: lat = None
            if lat is not None and lat <= MAX_PING_MS:
                s["ping"] = lat; working.append(s)
            done += 1
            if done % 25 == 0:
                print(f"  progress {done}/{len(eu)}, working: {len(working)}")
    print(f"Working <= {MAX_PING_MS}ms: {len(working)}")
    if not working:
        print("None working, keeping previous output."); return
    working.sort(key=lambda s: s["ping"])
    final = working[:MAX_SERVERS]
    print(f"Top {len(final)} servers selected.")
    out_lines = [randomize_name(s) for s in final]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode("\n".join(out_lines).encode("utf-8")).decode("ascii")
    OUTPUT_PATH.write_text(encoded, encoding="utf-8")
    print(f"Written {OUTPUT_PATH} ({len(out_lines)} servers)")

if __name__ == "__main__":
    main()