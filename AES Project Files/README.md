# 🔐 AES File Encryption Software

**Student:** Saud Hussain  
**Roll Number:** 0000948599  
**Subject:** Information Security Lab  
**Supervisor:** Sir Talha | **Theory:** Sir Yawar Abbas

---

## Overview

A desktop application that encrypts and decrypts any file using **AES-256-CBC** with **PBKDF2-HMAC-SHA256** key derivation. Built with Python 3 and Tkinter for a clean, educational GUI.

---

## Project Structure

```
aes_project/
├── aes_app.py         ← Main GUI application (run this)
├── crypto_engine.py   ← AES-256 encryption/decryption engine
├── test_crypto.py     ← Unit tests (8 test cases)
└── README.md
```

---

## Requirements

```bash
pip install pycryptodome
```

Python 3.8+ required. Tkinter is included with standard Python.

---

## How to Run

```bash
# Launch the GUI
python aes_app.py

# Run all unit tests
python test_crypto.py
```

---

## How It Works

### Encryption
1. A random **16-byte salt** is generated
2. A random **16-byte IV** (Initialization Vector) is generated
3. Password → **PBKDF2-HMAC-SHA256** (200,000 iterations) → 256-bit AES key
4. File is encrypted with **AES-256-CBC**
5. Output: `MAGIC_HEADER (9B) + SALT (16B) + IV (16B) + CIPHERTEXT`

### Decryption
1. Read and verify the magic header
2. Extract salt and IV from the file header
3. Re-derive the same key from the password using the stored salt
4. Decrypt and unpad the ciphertext

### Encrypted File Format

```
┌─────────────┬──────────────┬──────────────┬──────────────────────────┐
│ MAGIC (9B)  │  SALT (16B)  │   IV (16B)   │   CIPHERTEXT (variable)  │
│ "AESENC_V1" │  random      │  random      │   AES-256-CBC encrypted  │
└─────────────┴──────────────┴──────────────┴──────────────────────────┘
```

---

## Security Properties

| Property | Detail |
|---|---|
| Algorithm | AES-256-CBC |
| Key Size | 256 bits |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| KDF Iterations | 200,000 (NIST SP 800-132) |
| Salt | 128-bit random (per file) |
| IV | 128-bit random (per encryption) |
| Padding | PKCS#7 |

---

## References

- NIST FIPS 197 — AES Specification
- NIST SP 800-132 — PBKDF2 Recommendation  
- PyCryptodome Documentation
- Stallings, W. — Cryptography and Network Security (7th ed.)
