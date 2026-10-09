#!/usr/bin/env python3
"""Freedom-V2Ray filter - only VLESS + Shadowsocks, Europe (excl RU)."""
import base64, json, random, socket, sys, time
from pathlib import Path
from urllib.parse import quote, unquote
import requests

FUNDAMENTAL_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt"
MAX_SERVERS = 500
GEO_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,status"
OUTPUT_PATH = Path("output/mix_sub.txt")

ALLOWED_TYPES = {"vless", "ss"}  # ONLY these protocols

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

def parse_url_like(link, scheme):
    rest = link[len(scheme)+3:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "?" in rest: rest, _ = rest.split("?", 1)
    if "@" not in rest: return None
    _, hostport = rest.rsplit("@", 1)
    hostport = hostport.rstrip("/")
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    try: port = int(port)
    except Exception: return None
    return {"type":scheme,"host":host,"port":port,"raw":link}

def parse_ss(link):
    rest = link[5:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "@" in rest:
        _, hostport = rest.rsplit("@", 1)
        hostport = hostport.rstrip("/")
        if ":" not in hostport: return None
        host, port = hostport.rsplit(":", 1)
        try: port = int(port)
        except Exception: return None
        return {"type":"ss","host":host,"port":port,"raw":link}
    try: decoded = base64.b64decode(b64_pad(rest)).decode("utf-8", errors="ignore")
    except Exception: return None
    if "@" not in decoded: return None
    _, hostport = decoded.rsplit("@", 1)
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    try: port = int(port)
    except Exception: return None
    return {"type":"ss","host":host,"port":port,"raw":link}

def parse_server(link):
    link = link.strip()
    if link.startswith("vless://"): return parse_url_like(link, "vless")
    if link.startswith("ss://"):    return parse_ss(link)
    return None  # skip vmess, trojan, anything else

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
    # vless and ss use # fragment
    base = s["raw"].split("#", 1)[0]
    return f"{base}#{quote(name)}"

def main():
    print("=== Freedom filter (VLESS + SS only, Europe) ===")
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

    print(f"VLESS: {counts['vless']}, Shadowsocks: {counts['ss']}, skipped (vmess/trojan/other): {counts['skipped']}")
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

    if not eu:
        print("No European servers, keeping previous output."); return

    random.shuffle(eu)
    final = eu[:MAX_SERVERS]
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