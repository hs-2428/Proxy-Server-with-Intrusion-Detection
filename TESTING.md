# Testing Guide & Proof of Functionality

This document provides test cases and demonstrates the working functionality of the Proxy Server with Intrusion Detection System.

## 🖼️ Screenshots - Proof of Working System

### 1. Proxy Configuration
The proxy is configured in Firefox browser to use `127.0.0.1:8080` for both HTTP and HTTPS traffic.

![Proxy Configuration](docs/screenshots/proxy-settings.png)

### 2. Dashboard - Real-time Monitoring
The live dashboard shows real-time statistics and threat detection:
- Total Threats Detected: 5
- Requests Blocked: 5
- Active Connections: 5
- Live traffic graph showing threat detection timeline
- Attack distribution pie chart (all XSS attacks detected)

![Dashboard Overview](docs/screenshots/dashboard-overview.png)

### 3. Live Alerts - XSS Detection
Multiple XSS attacks detected and blocked in real-time with varying severity levels:
- Critical severity alerts shown in red
- Medium severity alerts shown in orange
- High severity alerts shown in orange
- Each alert includes timestamp and source IP (127.0.0.1)

![Live Alerts](docs/screenshots/live-alerts.png)

### 4. Intrusion Detection in Action
When an XSS attack is attempted, the proxy blocks it and displays:
```
Intrusion Detected.
```

The request to `testphp.vulnweb.com/search.php?test=query<script>alert('xss')</script>` was successfully blocked.

![Blocked Request](docs/screenshots/blocked-request.png)

## 🧪 Test Sites & Attack Patterns

### Recommended Testing Websites

#### 1. **OWASP WebGoat** (Educational)
```
http://webgoat.org/
```
A deliberately insecure application for learning web security.

#### 2. **DVWA (Damn Vulnerable Web Application)**
```
http://dvwa.co.uk/
```
Practice web vulnerabilities in a safe environment.

#### 3. **TestPHP Vulnweb** (Used in screenshots)
```
http://testphp.vulnweb.com/
```
- XSS Testing: `/search.php?test=<script>alert('xss')</script>`
- SQLi Testing: `/artists.php?artist=1' OR '1'='1`
- LFI Testing: `/showimage.php?file=../../etc/passwd`

#### 4. **HackThisSite**
```
https://www.hackthissite.org/
```
Legal hacking challenges and tutorials.

### Test Payloads by Attack Type

#### SQL Injection Tests
```
# Basic SQLi
' OR '1'='1
1' UNION SELECT NULL--
admin' --
' OR 1=1--

# Time-based SQLi
1' AND SLEEP(5)--
1' WAITFOR DELAY '0:0:5'--
```

#### Cross-Site Scripting (XSS) Tests
```
# Basic XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>

# Advanced XSS
<script>document.cookie</script>
<script>prompt('XSS')</script>
javascript:alert('XSS')
<IMG SRC="javascript:alert('XSS');">
```

#### Local File Inclusion (LFI) Tests
```
# Unix/Linux
../../etc/passwd
../../../etc/shadow
../../../../etc/hosts

# Windows
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\boot.ini
```

#### Command Injection Tests
```
; ls -la
| cat /etc/passwd
&& whoami
; id
&& ls -la
```

#### XXE Injection Tests
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

#### SSRF Tests
```
http://localhost
http://127.0.0.1
http://0.0.0.0
file:///etc/passwd
gopher://127.0.0.1:8080/
dict://127.0.0.1:11211/
```

#### LDAP Injection Tests
```
*)(uid=*))(|(uid=*
admin*
*)(objectClass=*)
```

## 🔧 Setup Instructions for Testing

### 1. Start the Proxy Server
```bash
cd Proxy-Server-with-Intrusion-Detection
python app.py
```

Expected output:
```
🚀 Proxy server listening on port 8080
📊 Dashboard available at http://127.0.0.1:5000
```

### 2. Configure Browser Proxy
**Firefox:**
1. Open Settings → Network Settings
2. Select "Manual proxy configuration"
3. HTTP Proxy: `127.0.0.1`, Port: `8080`
4. Check "Also use this proxy for HTTPS"
5. HTTPS Proxy: `127.0.0.1`, Port: `8080`

**Chrome:**
1. Settings → System → Open proxy settings
2. Manual proxy configuration
3. HTTP/HTTPS Proxy: `127.0.0.1:8080`

### 3. Access Dashboard
Open a new browser window (without proxy) and navigate to:
```
http://127.0.0.1:5000
```

### 4. Test Attack Detection
In the browser with proxy enabled, try these URLs:

**XSS Test:**
```
http://testphp.vulnweb.com/search.php?test=<script>alert('xss')</script>
```

**SQLi Test:**
```
http://testphp.vulnweb.com/artists.php?artist=' OR '1'='1
```

**LFI Test:**
```
http://testphp.vulnweb.com/showimage.php?file=../../etc/passwd
```

### 5. Monitor Results
- Check the dashboard for real-time alerts
- View the attack distribution chart
- Check `proxy_activity.log` for detailed logs

## 📊 Expected Results

### Successful Detection Indicators:
1. ✅ Browser shows "Intrusion Detected" message
2. ✅ Dashboard increments "Total Threats Detected" counter
3. ✅ Live alert appears in the "Live Alerts" section
4. ✅ Attack distribution chart updates
5. ✅ Entry added to `proxy_activity.log`
6. ✅ Console shows: `🚨 [INTRUSION ALERT - IP] Attack type: XXX`

### Rate Limiting Test:
Refresh a page rapidly (>100 times in a minute) to trigger rate limiting:
- ✅ "429 Too Many Requests" error
- ✅ IP added to blocked list
- ✅ Dashboard shows blocked IP in `/api/blocked_ips`

### Caching Test:
Visit the same GET request twice:
- ✅ Second request served from cache (faster)
- ✅ Dashboard shows incremented "Cached Responses" count
- ✅ Log shows "Served cached response for URL"

## 🛡️ Security Notes

- All tests should be performed on designated testing websites only
- Never use these payloads on production systems
- This is for educational purposes only
- Always obtain proper authorization before security testing

## 📝 Verification Checklist

- [ ] Proxy server starts without errors
- [ ] Dashboard accessible at port 5000
- [ ] Browser proxy configuration working
- [ ] XSS attacks detected and blocked
- [ ] SQLi attempts detected and blocked
- [ ] LFI attempts detected and blocked
- [ ] Dashboard shows real-time statistics
- [ ] Live alerts display correctly
- [ ] Attack distribution chart updates
- [ ] Logs written to proxy_activity.log
- [ ] Rate limiting works (429 error)
- [ ] Caching reduces load times
- [ ] Domain blocking functions properly
- [ ] All API endpoints respond correctly

## 🔗 Additional Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Web Security Academy**: https://portswigger.net/web-security
- **HackTheBox**: https://www.hackthebox.eu/
- **TryHackMe**: https://tryhackme.com/

---

**Last Updated**: November 4, 2025  
**Version**: 1.0.0  
**Team**: hs-2428
