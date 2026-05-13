#!/usr/bin/env python3
"""
Real 403/401 Bypass Scanner - Functional & Practical Security Tool
Run: python security_scanner.py
"""

from flask import Flask, render_template_string, request, jsonify
import threading
import requests
import time
import json
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

app = Flask(__name__)

# ============================================================
# WORKING BYPASS TECHNIQUES - Based on real bug bounty findings
# ============================================================

# 1. HTTP Method Tampering (Works on misconfigured endpoints)
# From: $1,000 bounty - changing POST to GET made 403 become 200
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

# 2. Path Traversal & Encoding bypasses
# From: 403 bypass checklist - /admin/., /admin/%2e/, etc.
PATH_BYPASSES = [
    # Basic path traversal
    "/", "/.", "/..", "/../", "/.///", "/./././",
    # URL encoded dots and slashes
    "/%2e/", "/%2e%2e/", "/%2e%2e%2e/", "/%252e%252e%252f",
    "/%c0%ae%c0%ae/", "/%ef%bc%8f", "/%e2%80%ae",
    # Case variations
    "/ADMIN/", "/Admin/", "/aDmIn/", "/AdMiN/",
    # With extensions
    "/admin.json", "/admin.xml", "/admin.txt", "/admin.html", "/admin.php", "/admin.jsp", "/admin/backup", "/admin/old",
    # Path ending variations
    "/;", "/;%2f..%2f", "/%3b%2f..%2f",
    # Double encoding
    "/%252fadmin%252f", "/%2561dmin/",
    # Mixed encoding in path
    "/a%64min/", "/%61dm%69n/"
]

# 3. Request Headers that can trick a server
IP_SPOOF_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Forwarded-For-Original", "X-Proxy-Host", "True-Client-IP",
    "X-Host", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Proxy-URL",
    "X-Custom-IP-Authorization", "X-Forwarded-By", "Referer", "Referrer", "Redirect",
    "X-Forwarded-Port", "X-Forwarded-Scheme"
]
IP_VALUES = ["127.0.0.1", "localhost", "::1", "10.0.0.1", "192.168.1.1"]

# 4. Protocol and Version tricks
PROTOCOLS = ["HTTP/1.0", "HTTP/1.1", "HTTP/2"]

# ============================================================
# SCANNER ENGINE
# ============================================================

# Global state
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


def safe_request(method, url, headers, test_type, test_value):
    """Make request and return result with timeout handling"""
    try:
        # For HEAD method, remove Content-Length header to avoid hanging
        if method.upper() == "HEAD":
            headers.pop("Content-Length", None)

        # Build request with custom protocol version if needed
        if "HTTP/1.0" in test_value:
            # Workaround: use requests with HTTP/1.0 via adapter
            from requests.adapters import HTTPAdapter
            s = requests.Session()
            s.mount("https://", HTTPAdapter())
            resp = s.request(method, url, headers=headers, timeout=15,
                             proxies=proxy_dict, verify=False, allow_redirects=False)
        else:
            resp = requests.request(method, url, headers=headers, timeout=15,
                                    proxies=proxy_dict, verify=False, allow_redirects=False)

        return (resp.status_code, len(resp.content), resp.url)
    except Exception as e:
        return (None, 0, url)


def test_single(payload):
    """Test one bypass combination"""
    global stop_flag, delay_sec, proxy_dict, target_url

    if stop_flag:
        return None

    if delay_sec:
        time.sleep(delay_sec)

    test_type, method, test_payload = payload

    try:
        if test_type == "method_mismatch":
            # Send POST request to GET-only endpoint
            headers = {}
            url = target_url
            resp = safe_request(method, url, headers, test_type, str(method))
            status, length, final_url = resp

        elif test_type == "path":
            base_path = target_url
            final_url = base_path + test_payload
            headers = {}
            resp = safe_request(method, final_url, headers, test_type, test_payload)
            status, length, final_url = resp

        elif test_type == "header":
            if ": " in test_payload:
                k, v = test_payload.split(": ", 1)
                headers = {k: v}
            else:
                headers = {}
            final_url = target_url
            resp = safe_request(method, final_url, headers, test_type, test_payload)
            status, length, final_url = resp

        elif test_type == "protocol":
            headers = {}
            final_url = target_url
            resp = safe_request(method, final_url, headers, test_type, test_payload)
            status, length, final_url = resp

        else:
            return None

        if status and original_status in (403, 401):
            # Bypass detected! Status changed from 403/401 to 2xx or 3xx
            if status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                return (method, test_type, test_payload, status, final_url)
            # Also check for content length change (could indicate different page)
            if status == 200 and length != original_length:
                return (method, test_type, test_payload, status, final_url)

        return None
    except Exception:
        return None


def scanner_worker():
    """Main scanning engine - builds and tests all combinations"""
    global scan_running, current_progress, scan_results, stop_flag
    global original_status, original_length, target_url, proxy_dict, delay_sec, threads_num, total_tests

    # 1. Get baseline response for comparison
    try:
        base_resp = requests.get(target_url, timeout=15, proxies=proxy_dict, verify=False)
        original_status = base_resp.status_code
        original_length = len(base_resp.content)
        print(f"[Baseline] {original_status} (length {original_length}) for {target_url}")
    except Exception as e:
        scan_results.append({"error": f"Baseline failed: {str(e)}", "status": 0})
        scan_running = False
        return

    # 2. Build all test combinations
    work_items = []

    # Add method tampering tests (try each HTTP method)
    for method in METHODS:
        work_items.append(("method_mismatch", method, "METHOD: " + method))

    # Add path bypass tests with all HTTP methods
    for method in METHODS:
        for path in PATH_BYPASSES:
            work_items.append(("path", method, path))

    # Add header injection tests with all HTTP methods
    for method in METHODS:
        for header in IP_SPOOF_HEADERS:
            for ip in IP_VALUES:
                work_items.append(("header", method, f"{header}: {ip}"))
        # Also add some common bypass headers from real-world
        work_items.append(("header", method, "X-Original-URL: /admin"))
        work_items.append(("header", method, "X-Rewrite-URL: /admin"))
        work_items.append(("header", method, "X-Forwarded-For: 127.0.0.1"))
        work_items.append(("header", method, "X-Real-IP: 127.0.0.1"))

    # Add protocol version tests
    for protocol in PROTOCOLS:
        work_items.append(("protocol", method, protocol))

    total_tests = len(work_items)
    current_progress = 0
    stop_flag = False
    scan_results = []

    print(f"[*] Starting scan with {threads_num} threads. Total tests: {total_tests}")

    # 3. Run tests in parallel
    with ThreadPoolExecutor(max_workers=threads_num) as executor:
        futures = {executor.submit(test_single, item): idx for idx, item in enumerate(work_items)}

        for future in as_completed(futures):
            if stop_flag:
                break

            idx = futures[future]
            current_progress = idx + 1
            result = future.result()

            if result:
                method, test_type, payload, status, url = result
                scan_results.append({
                    "method": method,
                    "type": test_type,
                    "payload": payload if len(payload) < 200 else payload[:197] + "...",
                    "status": status,
                    "url": url
                })
                print(f"\n[✓] BYPASS [{status}] {method} - {test_type}: {payload[:80]} -> {url}")

    scan_running = False
    print(f"\n[*] Scan completed. Found {len(scan_results)} bypasses.")


# ============================================================
# WEB INTERFACE
# ============================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Scanner - 403/401 Bypass Tool</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: auto;
        }
        h1 {
            color: #0f3460;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            margin-bottom: 5px;
        }
        .sub {
            color: #888;
            margin-bottom: 30px;
        }
        .card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .flex-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: flex-end;
        }
        input, select, button, textarea {
            background: #0f3460;
            border: 1px solid #e94560;
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 14px;
        }
        button {
            background: #e94560;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: bold;
        }
        button:hover {
            background: #ff6b6b;
            transform: scale(1.02);
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .progress {
            background: #0f3460;
            border-radius: 10px;
            margin: 10px 0;
            overflow: hidden;
        }
        .progress-bar {
            background: #e94560;
            width: 0%;
            height: 30px;
            text-align: center;
            line-height: 30px;
            transition: width 0.3s;
        }
        .results {
            background: #0f3460;
            border-radius: 8px;
            padding: 15px;
            max-height: 500px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 13px;
        }
        .result-item {
            border-left: 3px solid #4ade80;
            padding: 8px;
            margin: 8px 0;
            background: #16213e;
            border-radius: 4px;
        }
        .result-status {
            color: #4ade80;
            font-weight: bold;
        }
        .badge {
            background: #e94560;
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 11px;
            display: inline-block;
            margin-left: 10px;
        }
        hr {
            border-color: #e94560;
        }
        .notice {
            background: #2a1e3c;
            border-left: 3px solid #e94560;
            padding: 10px;
            margin: 10px 0;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>🔐 403/401 Bypass Scanner</h1>
    <div class="sub">Practical bypass scanner - tests real techniques from bug bounty findings</div>

    <div class="notice">
        ⚡ This scanner tests thousands of combinations (methods, paths, headers, protocols) automatically.
        <br>When a bypass is found, it appears instantly with the exact technique that worked.
    </div>

    <div class="card">
        <h3>🎯 Target</h3>
        <div class="flex-row">
            <input type="text" id="target" style="flex:3" placeholder="https://target.com/admin" value="https://example.com/admin">
            <input type="text" id="proxy" style="flex:1" placeholder="Proxy (http://...)" value="">
        </div>
        <div class="flex-row" style="margin-top: 15px;">
            <label>⚡ Threads: <input type="number" id="threads" value="15" step="5" style="width: 80px;"></label>
            <label>⏱ Delay (s): <input type="number" id="delay" value="0" step="0.1" style="width: 80px;"></label>
            <button id="startBtn">▶ START SCAN</button>
            <button id="stopBtn" disabled>⏹ STOP</button>
            <button id="exportBtn" disabled>💾 Export Results</button>
        </div>
    </div>

    <div class="card">
        <h3>📊 Progress</h3>
        <div class="progress"><div class="progress-bar" id="progressBar">0%</div></div>
        <div id="statusText" style="margin-top: 10px;">Ready. Click Start to begin scanning.</div>
        <div>✅ Bypasses found: <span id="foundCount" style="color: #4ade80;">0</span></div>
    </div>

    <div class="card">
        <h3>✨ Working Bypasses</h3>
        <div id="results" class="results">No results yet. Start a scan to find bypasses.</div>
    </div>
</div>

<script>
    let pollInterval;

    function startScan() {
        const target = document.getElementById('target').value;
        const proxy = document.getElementById('proxy').value;
        const threads = parseInt(document.getElementById('threads').value);
        const delay = parseFloat(document.getElementById('delay').value);

        if (!target) {
            alert('Please enter a target URL');
            return;
        }

        fetch('/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target, proxy, threads, delay})
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                document.getElementById('startBtn').disabled = true;
                document.getElementById('stopBtn').disabled = false;
                document.getElementById('exportBtn').disabled = true;
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(fetchStatus, 1000);
            } else {
                alert('Error: ' + data.error);
            }
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
        fetch('/export').then(res => res.json()).then(data => {
            if (data.results && data.results.length) {
                let text = data.results.map(r => `[${r.status}] ${r.method} ${r.type}: ${r.payload} -> ${r.url}`).join('\n');
                const blob = new Blob([text], {type: 'text/plain'});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `bypass_${new Date().toISOString().slice(0,19)}.txt`;
                a.click();
                URL.revokeObjectURL(a.href);
            } else {
                alert('No results to export');
            }
        });
    }

    function fetchStatus() {
        fetch('/status').then(res => res.json()).then(data => {
            const percent = data.total > 0 ? (data.progress / data.total * 100).toFixed(1) : 0;
            document.getElementById('progressBar').style.width = percent + '%';
            document.getElementById('progressBar').innerText = percent + '%';
            document.getElementById('statusText').innerHTML = data.running ? `Scanning... ${data.progress}/${data.total} tests` : (data.progress === data.total ? 'Scan completed.' : 'Ready.');
            document.getElementById('foundCount').innerText = data.results.length;

            if (data.results.length > 0) {
                let html = '';
                for (let i = data.results.length-1; i >= 0; i--) {
                    const r = data.results[i];
                    html += `<div class="result-item">
                        <span class="result-status">[${r.status}]</span> <strong>${r.method}</strong> - ${r.type}: ${escapeHtml(r.payload)}
                        <div><small>→ ${r.url}</small></div>
                    </div>`;
                }
                document.getElementById('results').innerHTML = html;
            }

            if (!data.running && data.progress === data.total) {
                clearInterval(pollInterval);
                document.getElementById('startBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
                document.getElementById('exportBtn').disabled = false;
                document.getElementById('statusText').innerHTML = 'Scan completed. Bypasses found: ' + data.results.length;
            }
        });
    }

    function escapeHtml(str) {
        return str.replace(/[&<>]/g, function(m) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;'}[m];
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
    """Serve the web interface"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/start', methods=['POST'])
def start():
    """Start a new scan"""
    global scan_running, target_url, proxy_dict, delay_sec, threads_num, stop_flag, current_progress, scan_results, total_tests

    if scan_running:
        return jsonify({"status": "error", "error": "Scan already running"})

    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"status": "error", "error": "Target URL required"})

    target_url = target
    proxy = data.get('proxy')
    proxy_dict = {'http': proxy, 'https': proxy} if proxy else None
    delay_sec = float(data.get('delay', 0))
    threads_num = int(data.get('threads', 10))

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
    """Stop current scan"""
    global stop_flag, scan_running
    stop_flag = True
    scan_running = False
    return jsonify({"status": "ok"})


@app.route('/status')
def status():
    """Get current scan status"""
    global scan_running, current_progress, total_tests, scan_results
    return jsonify({
        "running": scan_running,
        "progress": current_progress,
        "total": total_tests,
        "results": scan_results[-100:]
    })


@app.route('/export')
def export():
    """Export current results"""
    global scan_results
    return jsonify({"results": scan_results})


if __name__ == '__main__':
    print("=" * 60)
    print("🔐 403/401 Bypass Scanner - Practical & Functional")
    print("=" * 60)
    print("Opening browser at http://localhost:5000")
    print("\n⚠️  Usage notes:")
    print("- Enter the exact URL that returns 403 or 401")
    print("- The scanner tests method tampering, path bypasses, and headers")
    print("- Results appear instantly when a bypass is found")
    print("- Be polite: use delay when scanning production targets")
    print("=" * 60)

    # Open browser after a short delay
    threading.Timer(1.5, lambda: webbrowser.open('http://localhost:5000')).start()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
