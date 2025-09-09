# 🔐 Secure File Storage System (AES-256)

## 🧠 Project Objective

This tool allows you to **securely encrypt and decrypt files** locally using AES-256 encryption (`cryptography.Fernet`). It also saves file metadata and uses SHA-256 hash to verify file integrity.

---

## ⚙️ Features

- 🔒 AES-256 encryption (Fernet)
- 📝 Metadata saved: original filename, time, hash
- 🔐 Encrypted files stored as `.enc`
- 🧪 Hash verification on decryption
- ✅ CLI interface

---

## 🚀 How to Use

### 1. Install Requirements

```bash
pip install -r requirements.txt
