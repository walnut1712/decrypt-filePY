"""
AES-256-CBC Decryption Script for OpenSSL Encrypted Files
==========================================================
Cyber Forensics Assignment
Algorithm : AES-256-CBC (OpenSSL format)
Key Derivation : EVP_BytesToKey (MD5-based)
"""

import hashlib
from os.path import exists
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────
# STEP 1 – Key & IV Derivation
# ─────────────────────────────────────────────
def evp_bytes_to_key(password: bytes, salt: bytes,
                     key_len: int = 32, iv_len: int = 16):
    """
    Replicates OpenSSL's EVP_BytesToKey() with MD5 and count=1.

    OpenSSL does NOT store the key or IV in the file. Instead it
    re-derives them every time from:
        password  – supplied by the user
        salt      – random 8 bytes stored in bytes 8-15 of the file

    The derivation loop concatenates MD5 digests until enough bytes
    are produced for both the key and the IV.

    Returns
    -------
    key : bytes  – 32 bytes  (AES-256)
    iv  : bytes  – 16 bytes  (AES block size)
    """
    material = b""
    prev = b""
    while len(material) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        material += prev
    return material[:key_len], material[key_len:key_len + iv_len]


# ─────────────────────────────────────────────
# STEP 2 – Main Decryption Function
# ─────────────────────────────────────────────
def decrypt_openssl_file(encrypted_path: str,
                         password: str,
                         output_path: str = None) -> str | None:
    """
    Decrypt an OpenSSL AES-256-CBC encrypted file.

    OpenSSL file layout (binary):
    ┌─────────────┬──────────┬──────────────────────┐
    │ b'Salted__' │  8-byte  │  Ciphertext (padded  │
    │  (8 bytes)  │   salt   │  to 16-byte blocks)  │
    └─────────────┴──────────┴──────────────────────┘

    Parameters
    ----------
    encrypted_path : path to the .txt / .enc file
    password       : decryption password (string)
    output_path    : if provided, save plaintext here

    Returns
    -------
    Decrypted text as a string, or None on failure.
    """

    # ── 2a. Read the encrypted file ──────────────────────────────
    if not exists(encrypted_path):
        print(f"[ERROR] File not found: {encrypted_path}")
        return None

    with open(encrypted_path, "rb") as f:
        raw = f.read()

    print(f"[*] File size          : {len(raw)} bytes")

    # ── 2b. Validate OpenSSL magic header ────────────────────────
    if raw[:8] != b"Salted__":
        print("[WARNING] 'Salted__' header missing – may not be OpenSSL format")
    else:
        print("[+] OpenSSL 'Salted__' header confirmed")

    # ── 2c. Extract salt and ciphertext ──────────────────────────
    salt = raw[8:16]          # bytes 8-15
    ciphertext = raw[16:]           # everything after the header
    print(f"[+] Salt (hex)         : {salt.hex()}")
    print(f"[*] Ciphertext size    : {len(ciphertext)} bytes")

    # ── 2d. Derive Key + IV ───────────────────────────────────────
    key, iv = evp_bytes_to_key(password.encode("utf-8"), salt)
    print(f"[+] Derived key (hex)  : {key.hex()}")
    print(f"[+] Derived IV  (hex)  : {iv.hex()}")

    # ── 2e. AES-256-CBC Decryption ───────────────────────────────
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # ── 2f. Remove PKCS7 Padding ─────────────────────────────────
    # The last byte tells us how many padding bytes were appended
    pad_len = padded[-1]
    plaintext_bytes = padded[:-pad_len] if 0 < pad_len <= 16 else padded

    # ── 2g. Decode to text ───────────────────────────────────────
    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext = plaintext_bytes.decode("ascii", errors="replace")

    print("\n[+] Decryption successful!")
    print("=" * 50)
    print("DECRYPTED CONTENT:")
    print("=" * 50)
    print(plaintext)
    print("=" * 50)

    # ── 2h. Optionally save output ───────────────────────────────
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(plaintext)
        print(f"\n[+] Saved to: {output_path}")

    return plaintext


# ─────────────────────────────────────────────
# STEP 3 – Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":

    ENCRYPTED_FILE = "encrypted.txt"
    PASSWORD_FILE = "aes_passwrd.txt"
    OUTPUT_FILE = "decrypted.txt"

    # Read password from file
    try:
        with open(PASSWORD_FILE, "r") as f:
            password = f.read().strip()
        print(f"[+] Password loaded from '{PASSWORD_FILE}': {password}\n")
    except FileNotFoundError:
        password = "123456789"
        print(f"[*] Password file not found – using default: {password}\n")

    decrypt_openssl_file(ENCRYPTED_FILE, password, OUTPUT_FILE)
