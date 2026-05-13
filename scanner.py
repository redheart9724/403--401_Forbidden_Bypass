#!/usr/bin/env python3
"""
403/401 Bypass Scanner – Test thousands of payloads against a target.
Usage: python scanner.py -u https://target.com/admin -p payloads.json
"""

import requests
import sys
import json
import argparse
import time
from urllib.parse import urlparse, quote

def load_payloads(json_file):
    with open(json_file, 'r') as f:
        return json.load(f)

def test_payload(target_url, payload, method='GET', delay=0):
    """Send request with a header or path modification."""
    if delay:
        time.sleep(delay)
    try:
        if payload.startswith('PATH: '):
            # Path bypass
            suffix = payload.replace('PATH: ', '')
            test_url = target_url.rstrip('/') + suffix
            headers = {}
        elif ': ' in payload:
            # Header
            header_name, header_value = payload.split(': ', 1)
            headers = {header_name: header_value}
            test_url = target_url
        else:
            # raw header line
            parts = payload.split(': ', 1)
            if len(parts) == 2:
                headers = {parts[0]: parts[1]}
            else:
                headers = {}
            test_url = target_url
        resp = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
        return resp.status_code, len(resp.content), test_url
    except Exception as e:
        return None, 0, None

def main():
    parser = argparse.ArgumentParser(description='403/401 Bypass Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://target.com/admin)')
    parser.add_argument('-p', '--payloads', required=True, help='JSON file with payloads (exported from HTML)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests (seconds)')
    parser.add_argument('-o', '--output', default='working_bypasses.txt', help='Output file')
    args = parser.parse_args()

    print(f"[*] Loading payloads from {args.payloads}")
    payloads = load_payloads(args.payloads)
    print(f"[*] Total payloads: {len(payloads)}")

    # Get baseline
    try:
        baseline = requests.get(args.url, timeout=10)
        original_status = baseline.status_code
        original_length = len(baseline.content)
        print(f"[*] Original response: {original_status} (length {original_length})")
        if original_status != 403 and original_status != 401:
            print("[!] Target is not 403/401 – still scanning for interesting changes.")
    except:
        print("[-] Cannot reach target")
        sys.exit(1)

    working = []
    for idx, p in enumerate(payloads, 1):
        sys.stdout.write(f"\r[{idx}/{len(payloads)}] Testing: {p[:50]}...")
        sys.stdout.flush()
        status, length, test_url = test_payload(args.url, p, delay=args.delay)
        if status and original_status in [403,401] and status in [200,201,202,204,301,302,303,307,308]:
            working.append((p, status, test_url))
            print(f"\n[✓] BYPASS! {p} -> {status} on {test_url}")
        elif status == 200 and length != original_length:
            working.append((p, status, test_url))
            print(f"\n[✓] BYPASS (content changed)! {p} -> {status} (len {length})")

    print(f"\n\n[*] Scan finished. Found {len(working)} bypass(es).")
    if working:
        with open(args.output, 'w') as f:
            for w in working:
                f.write(f"{w[0]} -> HTTP {w[1]} [{w[2]}]\n")
        print(f"[+] Results saved to {args.output}")
    else:
        print("[-] No bypass found.")

if __name__ == '__main__':
    main()