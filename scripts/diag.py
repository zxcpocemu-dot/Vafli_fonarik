import base64, json, os, subprocess, sys, tempfile, time, socket
sys.path.insert(0, 'scripts')
import main

r = main.requests.get(main.FUNDAMENTAL_URL, timeout=30)
decoded = base64.b64decode(main.b64_pad(r.text.strip())).decode('utf-8', errors='ignore')

candidates = []
for line in decoded.splitlines():
    s = main.parse_server(line.strip())
    if s and s['type'] in ('vless','trojan','vmess'):
        candidates.append(s)
        if len(candidates) >= 3:
            break

print(f"Found {len(candidates)} candidate servers")
xray = main.ensure_xray()
print(f"xray: {xray}, exists={xray.exists()}, size={xray.stat().st_size if xray.exists() else 0}")

for s in candidates:
    print(f"\n--- {s['type']} {s['host']}:{s['port']} ---")
    ob = main.build_outbound(s)
    if not ob:
        print("  build_outbound returned None"); continue
    print(f"  outbound protocol={ob.get('protocol')}, network={ob.get('streamSettings',{}).get('network','?')}")

    port = 10808
    cfg = {'log':{'loglevel':'debug'},
           'inbounds':[{'port':port,'listen':'127.0.0.1','protocol':'socks','settings':{'udp':False,'auth':'noauth'}}],
           'outbounds':[ob]}
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
        json.dump(cfg, f, indent=2); cfg_path = f.name

    proc = subprocess.Popen([str(xray), 'run', '-c', cfg_path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 3
    started = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            sock = socket.create_connection(('127.0.0.1', port), timeout=0.2); sock.close()
            started = True; break
        except Exception:
            time.sleep(0.1)

    if not started:
        try: proc.wait(timeout=2)
        except Exception: proc.kill()
        out, err = proc.communicate(timeout=2)
        print(f"  XRAY DID NOT START. exit_code={proc.returncode}")
        print(f"  --- stdout ---\n{out[-800:]}")
        print(f"  --- stderr ---\n{err[-1500:]}")
        try: os.unlink(cfg_path)
        except: pass
        continue

    print(f"  xray started on port {port}")
    try:
        start = time.perf_counter()
        resp = main.requests.get('http://cp.cloudflare.com/generate_204',
                                 proxies={'http': f'socks5h://127.0.0.1:{port}',
                                          'https': f'socks5h://127.0.0.1:{port}'},
                                 timeout=8)
        lat = (time.perf_counter() - start) * 1000
        print(f"  HTTP status={resp.status_code}, latency={lat:.0f}ms")
    except Exception as e:
        print(f"  HTTP FAILED: {type(e).__name__}: {e}")

    proc.terminate()
    try: proc.wait(timeout=2)
    except Exception: proc.kill()
    try:
        out, err = proc.communicate(timeout=2)
        if err:
            print(f"  --- xray stderr (tail) ---\n{err[-800:]}")
    except Exception: pass
    try: os.unlink(cfg_path)
    except: pass

print("\n=== DONE ===")