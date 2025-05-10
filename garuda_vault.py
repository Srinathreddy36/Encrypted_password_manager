import os
import json
import base64
import hashlib
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256  # ✅ CORRECT MODULE FOR PBKDF2

AUTH_FILE = 'auth.json'
VAULT_FILE = 'vault.dat'
SALT_SIZE = 16
KEY_LEN = 32
ITERATIONS = 100_000

# ✅ Use ONLY this derive_key definition
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERATIONS, hmac_hash_module=SHA256)

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def save_auth(salt, key_hash):
    with open(AUTH_FILE, 'w') as f:
        json.dump({
            'salt': base64.b64encode(salt).decode(),
            'key_hash': key_hash.hex()
        }, f)

def load_auth():
    with open(AUTH_FILE, 'r') as f:
        data = json.load(f)
        return base64.b64decode(data['salt']), bytes.fromhex(data['key_hash'])

def encrypt_data(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    return iv + encrypted

def decrypt_data(key, encrypted):
    iv = encrypted[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted[16:]))

# Step 1: Master Password Setup or Verification
if not os.path.exists(AUTH_FILE):
    print("[*] First-time setup.")
    password = getpass.getpass("Set a master password: ")
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    key_hash = hashlib.sha3_256(key).digest()
    save_auth(salt, key_hash)
    print("[+] Master password set.")
else:
    password = getpass.getpass("Enter master password: ")
    salt, stored_hash = load_auth()
    key = derive_key(password.encode(), salt)
    key_hash = hashlib.sha3_256(key).digest()
    if key_hash != stored_hash:
        print("[!] Access denied: Wrong password.")
        exit()

# Step 2: Input credentials
site = input("Site name: ")
username = input("Username: ")
passwd = getpass.getpass("Password: ")

entry = {
    'site': site,
    'username': username,
    'password': passwd
}

# Step 3: Encrypt and store vault
vault_data = [entry]

if os.path.exists(VAULT_FILE):
    with open(VAULT_FILE, 'rb') as f:
        decrypted = decrypt_data(key, f.read())
        vault_data = json.loads(decrypted.decode())
        vault_data.append(entry)

with open(VAULT_FILE, 'wb') as f:
    encrypted = encrypt_data(key, json.dumps(vault_data).encode())
    f.write(encrypted)

print(f"[+] Credentials saved securely in {VAULT_FILE}")
