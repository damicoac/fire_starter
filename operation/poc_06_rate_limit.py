#!/usr/bin/env python3
"""
PoC for Rate Limiting Bypass on 192.168.64.4
Vulnerability: No rate limiting on repeated requests
"""
import urllib.request
import time

target = "http://192.168.64.4"

print("[+] Rate Limiting PoC")
print(f"[*] Target: {target}")
print("-" * 60)

# Send rapid requests and check for HTTP 429 responses
num_requests = 50
print(f"[*] Sending {num_requests} rapid requests...")

blocked_count = 0
success_count = 0
start_time = time.time()

for i in range(num_requests):
    try:
        req = urllib.request.Request(target)
        with urllib.request.urlopen(req, timeout=2) as response:
            if response.status == 429:
                blocked_count += 1
            else:
                success_count += 1
    except urllib.error.HTTPError as e:
        if e.code == 429:
            blocked_count += 1
        else:
            success_count += 1
    except Exception:
        pass

elapsed = time.time() - start_time

print(f"\n[Results]")
print(f"   Total requests: {num_requests}")
print(f"   Successful responses: {success_count}")
print(f"   Blocked (HTTP 429): {blocked_count}")
print(f"   Time elapsed: {elapsed:.2f} seconds")
print(f"   Requests per second: {num_requests/elapsed:.1f}")

if blocked_count == 0 and success_count > 40:
    print(f"\n   [!] VULNERABLE: No rate limiting detected!")
    print(f"       All {success_count} requests were accepted")
else:
    print(f"\n   [-] Rate limiting appears to be in place")

print("\n[+] Rate Limiting PoC complete")
