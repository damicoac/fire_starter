import urllib.request
import urllib.parse
import http.cookiejar
import re
import sys

# Setup cookie jar
cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
urllib.request.install_opener(opener)

url = 'http://192.168.64.4/DVWA/login.php'

try:
    # Get login page to extract user_token
    req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req)
    html = resp.read().decode('utf-8')
    
    # Extract user_token
    match = re.search(r"name='user_token' value='([a-f0-9]+)'", html)
    if not match:
        print("Error: Could not find user_token in login page")
        sys.exit(1)
        
    user_token = match.group(1)
    
    # POST to login
    data = urllib.parse.urlencode({
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': user_token
    }).encode('utf-8')
    
    req_post = urllib.request.Request(url, data=data)
    resp_post = urllib.request.urlopen(req_post)
    
    # Print cookies
    cookies = []
    for c in cookie_jar:
        cookies.append(f"{c.name}={c.value}")
    cookies.append("security=low") # set security to low for testing
    print("; ".join(cookies))
except Exception as e:
    print(f"Exception: {e}")
