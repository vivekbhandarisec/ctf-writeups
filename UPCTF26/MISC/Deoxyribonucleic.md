# upCTF — Deoxyribonucleic acid

**Category:** Misc / Crypto
**Points:** 356
**Solves:** 13

---

## 📖 Challenge Description

The challenge provided a DNA-like ciphertext consisting only of the characters **A, C, G, T** and a substitution table:

```
          | 0 | 1 | 2
----------|---|---|---
A         | C | G | T
C         | G | T | A
G         | T | A | C
T         | A | C | G
```

Ciphertext:

```
ACTCTACGAGTCTACAGAGTCGTCGTATCAGTCTCACGTGAGCGAGTATACAGTGTCGAGCGTGCGACTCGCTACAGAGTCGCTGTAGCACGAGTCTAGTGTGTCGATCGAGTGTAGTCTGTCGTCGTCGCTGTAGCACGAGTATAGTCTGTCGTAGTAGCAGTATGATAGAGCA
```

---

## 🔎 Observations

* The ciphertext contains only **DNA bases**: `A C G T`.
* The table shows **three possible substitutions** for each base depending on a value **0, 1, or 2**.
* This strongly suggests a **repeating key cipher with key length = 3**.
* After reversing the substitution, the DNA string can be converted into **binary and then ASCII**.

---

## 🧠 Attack Strategy

1. Build the **reverse substitution table** from the provided mapping.
2. Assume a **3-digit key** where each digit ∈ {0,1,2}.
3. Try all possible keys (**3³ = 27 possibilities**).
4. For each key:

   * Reverse the DNA substitution.
   * Convert DNA bases to binary using:

```
A → 00
C → 01
G → 10
T → 11
```

5. Convert the binary stream to ASCII text.
6. Check for a string containing the flag format `upCTF{...}`.

---

## 🧑‍💻 Solver Script

```python
import itertools

cipher = "ACTCTACGAGTCTACAGAGTCGTCGTATCAGTCTCACGTGAGCGAGTATACAGTGTCGAGCGTGCGACTCGCTACAGAGTCGCTGTAGCACGAGTCTAGTGTGTCGATCGAGTGTAGTCTGTCGTCGTCGCTGTAGCACGAGTATAGTCTGTCGTAGTAGCAGTATGATAGAGCA"

table = {
'A':['C','G','T'],
'C':['G','T','A'],
'G':['T','A','C'],
'T':['A','C','G']
}

rev = {}
for k,v in table.items():
    for i,c in enumerate(v):
        rev.setdefault(i,{})[c] = k

dna_bin = {'A':'00','C':'01','G':'10','T':'11'}

for key in itertools.product(range(3), repeat=3):
    p = ""
    for i,c in enumerate(cipher):
        k = key[i%3]
        p += rev[k][c]

    bits = "".join(dna_bin[x] for x in p)

    msg = ""
    for i in range(0,len(bits),8):
        msg += chr(int(bits[i:i+8],2))

    if "upCTF{" in msg:
        print(msg)
```

---

## 🏁 Flag

```
upCTF{DnA_IsCh3pear_Th3n_R4M}
```

---

## 💡 Key Takeaway

DNA-based encodings in CTF challenges often use:

* The alphabet **A, C, G, T**
* Binary mappings such as `A=00, C=01, G=10, T=11`
* Small repeating substitution keys

Because the key space is small, **brute-forcing the key and checking for readable ASCII is usually enough to recover the flag**.
