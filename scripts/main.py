#!/usr/bin/env python3
"""Freedom-V2Ray filter - multi-source, geo filter only."""
import base64, json, random, socket, sys, time
from pathlib import Path
from urllib.parse import quote
import requests

SOURCES = [
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt",
    "https://codeberg.org/zieng2/wl/raw/branch/main/vless_universal.txt",
    "https://raw.githubusercontent.com/wlunlocker/vpn-configs/main/whitelist_all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
]
MAX_SERVERS = 1000
GEO_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,status"
OUTPUT_PATH = Path("output/mix_sub.txt")

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
    return f"{country_flag(cc)} {base} 🤩".strip()

def b64_pad(s):
    return s + "=" * (-len(s) % 4)

def fetch_source(url):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        text = r.text.strip()
        # try base64 decode first
        try:
            decoded = base64.b64decode(b64_pad(text)).decode("utf-8", errors="ignore")
            if any(proto in decoded for proto in ("vmess://","vless://","trojan://","ss://")):
                return decoded
        except Exception:
            pass
        return text
    except Exception as ex:
        print(f"  FAIL {url}: {ex}", file=sys.stderr)
        return ""

def parse_vmess(link):
    try:
        data = json.loads(base64.b64decode(b64_pad(link[8:])).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    if not data.get("add") or not data.get("port"): return None
    try: port = int(data["port"])
    except Exception: return None
    return {"type":"vmess","host":data["add"],"port":port,"raw":link,
            "key":("vmess", data["add"], port, data.get("id",""))}

def parse_url_like(link, scheme):
    rest = link[len(scheme)+3:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "?" in rest: rest, query = rest.split("?", 1)
    else: query = ""
    if "@" not in rest: return None
    userinfo, hostport = rest.rsplit("@", 1)
    hostport = hostport.rstrip("/")
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    try: port = int(port)
    except Exception: return None
    return {"type":scheme,"host":host,"port":port,"raw":link,
            "key":(scheme, host, port, userinfo)}

def parse_ss(link):
    rest = link[5:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        hostport = hostport.rstrip("/")
        if ":" not in hostport: return None
        host, port = hostport.rsplit(":", 1)
        try: port = int(port)
        except Exception: return None
        return {"type":"ss","host":host,"port":port,"raw":link,
                "key":("ss", host, port, userinfo)}
    try: decoded = base64.b64decode(b64_pad(rest)).decode("utf-8", errors="ignore")
    except Exception: return None
    if "@" not in decoded: return None
    userinfo, hostport = decoded.rsplit("@", 1)
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    try: port = int(port)
    except Exception: return None
    return {"type":"ss","host":host,"port":port,"raw":link,
            "key":("ss", host, port, userinfo)}

def parse_server(link):
    link = link.strip()
    if not link or link.startswith("#"): return None
    if link.startswith("vmess://"):  return parse_vmess(link)
    if link.startswith("vless://"):  return parse_url_like(link, "vless")
    if link.startswith("trojan://"): return parse_url_like(link, "trojan")
    if link.startswith("ss://"):     return parse_ss(link)
    return None

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
    print(f"=== Freedom filter (multi-source, {len(SOURCES)} sources) ===")
    all_servers = []
    seen_keys = set()
    for idx, url in enumerate(SOURCES, 1):
        print(f"[{idx}/{len(SOURCES)}] {url}")
        text = fetch_source(url)
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        found = 0
        dup = 0
        for line in lines:
            s = parse_server(line)
            if not s: continue
            if s["key"] in seen_keys:
                dup += 1
                continue
            seen_keys.add(s["key"])
            all_servers.append(s)
            found += 1
        print(f"   -> parsed={found}, duplicates skipped={dup}")
    print(f"Total unique servers: {len(all_servers)}")
    if not all_servers: return
    print("Geo lookup...")
    geo = geo_lookup([s["host"] for s in all_servers])
    eu = []
    for s in all_servers:
        cc = geo.get(s["host"])
        if cc and cc in ALLOWED:
            s["cc"] = cc; eu.append(s)
    print(f"Europe (excl. RU): {len(eu)}")
    if not eu:
        print("No European servers, keeping previous output."); return
    random.shuffle(eu)
    final = eu[:MAX_SERVERS]
    print(f"Selected: {len(final)} servers")
    out_lines = [randomize_name(s) for s in final]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode("\n".join(out_lines).encode("utf-8")).decode("ascii")
    OUTPUT_PATH.write_text(encoded, encoding="utf-8")
    print(f"Written {OUTPUT_PATH} ({len(out_lines)} servers)")

if __name__ == "__main__":
    main()