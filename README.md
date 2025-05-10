# 🔐 Garuda Vault

Garuda Vault is a secure, offline password manager built in Python. It encrypts your saved credentials using AES-CBC and protects the master key with PBKDF2 key derivation and SHA3-256 hashing. All vault data is stored locally in encrypted form.

## 📌 Features

- 🔒 Master password setup and verification
- 🔑 Key derivation using PBKDF2 with 100,000 iterations
- 🧂 Per-user unique random salt
- 🧠 SHA3-256 password hash for authentication
- 🔐 AES-256-CBC encryption of credential entries
- 🧾 Supports multiple site credentials
- 💾 Stores credentials securely in `vault.dat` file
- 📂 Everything is stored locally — no cloud involved

---

## 🚀 Getting Started
🔁 Adding Credentials
After successful login, you can store credentials for:

Site name

Username

Password

The data is appended to your encrypted vault file (vault.dat).

🔐 Security Design
PBKDF2 is used to derive a 256-bit key from your master password and a random salt.

The derived key is not stored directly — only its SHA3-256 hash is saved for authentication.

Vault entries are encrypted with AES-256-CBC, using a fresh IV each time.

Your salt and password hash are saved in auth.json (not in plaintext).

📁 Files
garuda_vault.py – Main program

auth.json – Stores salt and password hash

vault.dat – Encrypted vault containing saved credentials

⚠️ Warning
This is a local-only password manager — it does not sync to the cloud.

If you forget your master password, the vault cannot be recovered.

Always backup auth.json and vault.dat together.

📚 License
This project is part of the Garuda Sentinel mission for personal cybersecurity education and awareness.

✍️ Author
Srinath Reddy





### 🛠 Requirements

- Python 3.6+
- `pycryptodome` library


Install dependencies:

```bash
pip install pycryptodome

