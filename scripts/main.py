#!/usr/bin/env python3
"""
Freedom-V2Ray config filter.
- Downloads fundamental subscription
- Keeps only European countries (excluding Russia)
- Tests TCP latency, keeps < MAX_PING_MS
- Randomizes server names
- Publishes filtered subscription to output/mix_sub.txt
"""
import base64
import json
import random
import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import requests

FUNDAMENTAL_URL = "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix_sub.txt"
MAX_PING_MS = 150
PING_TIMEOUT = 3.0
GEO_BATCH_URL = "http://ip-api.com/batch?fields=query,countryCode,status"
OUTPUT_PATH = Path("output/mix_sub.txt")

EUROPE = {
    "AD","AL","AT","BA","BE","BG","BY","CH","CY","CZ","DE","DK","EE","ES","FI",
    "FO","FR","GB","GG","GI","GR","HR","HU","IE","IM","IS","IT","JE","LI","LT",
    "LU","LV","MC","MD","ME","MK","MT","NL","NO","PL","PT","RO","RS","SE",
    "SI","SK","SM","UA","VA","AX","XK",
}
EXCLUDE = {"RU"}
ALLOWED = EUROPE - EXCLUDE

ADJ = ["quiet","swift","bright","calm","bold","fancy","lucky","neat","proud","warm",
       "silent","golden","silver","wild","free","azure","noble","prime","vivid","pure"]
NOUN = ["meadow","river","star","forest","cloud","stone","wave","hill","moon","sun",
        "field","lake","peak","sky","wind","oak","pine","sage","vale","bay"]

def gen_name():
    return f"{random.choice(ADJ)}-{random.choice(NOUN)}-{random.randint(100,999)}"

def b64_pad(s):
    return s + "=" * (-len(s) % 4)

def parse_vmess(link):
    raw = b64_pad(link[8:])
    try:
        data = json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    host = data.get("add"); port = data.get("port")
    if not host or not port: return None
    try: port = int(port)
    except Exception: return None
    return {"type":"vmess","host":host,"port":port,"raw":link,"data":data}

def parse_url_like(link, scheme):
    rest = link[len(scheme)+3:]
    if "#" in rest: rest, _ = rest.split("#", 1)
    if "?" in rest: rest, _ = rest.split("?", 1)
    if "@" in rest:
        _, hostport = rest.rsplit("@", 1)
    else:
        hostport = rest
    hostport = hostport.rstrip("/")
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    host = host.strip("[]")
    try: port = int(port)
    except Exception: return None
    return {"type":scheme,"host":host,"port":port,"raw":link}

def parse_ss(link):
    rest = link[5:]
    if "#" in rest:
        rest, _ = rest.split("#", 1)
    if "?" in rest:
        rest, _ = rest.split("?", 1)
    if "@" in rest:
        _, hostport = rest.rsplit("@", 1)
        hostport = hostport.rstrip("/")
        if ":" not in hostport: return None
        host, port = hostport.rsplit(":", 1)
        try: port = int(port)
        except Exception: return None
        return {"type":"ss","host":host,"port":port,"raw":link}
    try:
        decoded = base64.b64decode(b64_pad(rest)).decode("utf-8", errors="ignore")
    except Exception:
        return None
    if "@" not in decoded: return None
    _, hostport = decoded.rsplit("@", 1)
    if ":" not in hostport: return None
    host, port = hostport.rsplit(":", 1)
    try: port = int(port)
    except Exception: return None
    return {"type":"ss","host":host,"port":port,"raw":link}

def parse_server(link):
    link = link.strip()
    if link.startswith("vmess://"):  return parse_vmess(link)
    if link.startswith("vless://"):  return parse_url_like(link, "vless")
    if link.startswith("trojan://"): return parse_url_like(link, "trojan")
    if link.startswith("ss://"):     return parse_ss(link)
    return None

def tcp_ping(host, port, timeout=PING_TIMEOUT):
    try:
        start = time.perf_counter()
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return None

def geo_lookup(hosts):
    result = {}
    ip_to_host = {}
    for h in hosts:
        try:
            ip = socket.gethostbyname(h)
        except Exception:
            continue
        ip_to_host[ip] = h
    ips = list(ip_to_host.keys())
    for i in range(0, len(ips), 100):
        chunk = ips[i:i+100]
        payload = [{"query": ip} for ip in chunk]
        try:
            r = requests.post(GEO_BATCH_URL, json=payload, timeout=30)
            r.raise_for_status()
            for entry in r.json():
                if entry.get("status") == "success":
                    result[ip_to_host[entry["query"]]] = entry.get("countryCode")
        except Exception as e:
            print(f"  geo batch error: {e}", file=sys.stderr)
        time.sleep(1)
    return result

def randomize_name(server):
    name = gen_name()
    t = server["type"]; raw = server["raw"]
    if t == "vmess":
        data = dict(server["data"])
        data["ps"] = name
        encoded = base64.b64encode(
            json.dumps(data, separators=(",", ":")).encode()
        ).decode()
        return "vmess://" + encoded
    base = raw.split("#", 1)[0]
    return f"{base}#{quote(name)}"

def main():
    print("=== Freedom-V2Ray filter ===")
    print(f"Downloading: {FUNDAMENTAL_URL}")
    r = requests.get(FUNDAMENTAL_URL, timeout=30)
    r.raise_for_status()
    try:
        decoded = base64.b64decode(b64_pad(r.text.strip())).decode("utf-8", errors="ignore")
    except Exception:
        decoded = r.text
    lines = [l.strip() for l in decoded.splitlines() if l.strip()]
    print(f"Total lines: {len(lines)}")

    servers = [s for s in (parse_server(l) for l in lines) if s]
    print(f"Parsed: {len(servers)}")
    if not servers:
        print("Nothing parsed. Aborting."); return

    print("Geo lookup...")
    geo = geo_lookup([s["host"] for s in servers])
    europe_servers = []
    for s in servers:
        cc = geo.get(s["host"])
        if cc and cc in ALLOWED:
            s["cc"] = cc
            europe_servers.append(s)
    print(f"Europe (excl. RU): {len(europe_servers)}")
    if not europe_servers:
        print("No European servers. Aborting to keep previous output."); return

    print(f"Ping test (threshold {MAX_PING_MS} ms, timeout {PING_TIMEOUT}s)...")
    working = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(tcp_ping, s["host"], s["port"]): s for s in europe_servers}
        for fut in as_completed(futs):
            s = futs[fut]
            try:
                ms = fut.result()
            except Exception:
                ms = None
            if ms is not None and ms <= MAX_PING_MS:
                s["ping"] = ms
                working.append(s)
    print(f"Working & fast: {len(working)}")
    if not working:
        print("No working servers. Aborting."); return

    working.sort(key=lambda s: s["ping"])
    final = [randomize_name(s) for s in working]
    print(f"Final: {len(final)} servers")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joined = "\n".join(final)
    encoded = base64.b64encode(joined.encode("utf-8")).decode("ascii")
    OUTPUT_PATH.write_text(encoded, encoding="utf-8")
    print(f"Written: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()