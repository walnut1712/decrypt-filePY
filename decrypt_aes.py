"""
AES Decryption Script for OpenSSL Encrypted Files
This script decrypts files encrypted with OpenSSL using EVP_BytesToKey
"""

import hashlib
import sys
from os.path import exists


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
    """
    Equivalent to OpenSSL's EVP_BytesToKey() with count=1
    Used to derive key and IV from a password and salt
    """
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password + salt
        if i > 0:
            data = m[i - 1] + password + salt
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    return ms[:key_len], ms[key_len:key_len + iv_len]


def decrypt_file(encrypted_file: str, password: str, output_file: str = None):
    """
    Decrypt OpenSSL encrypted file using AES-256-CBC

    Args:
        encrypted_file: Path to encrypted file
        password: Decryption password
        output_file: Path to save decrypted output (optional)

    Returns:
        Decrypted data as string
    """
    try:
        # Read encrypted file
        if not exists(encrypted_file):
            print(f"[ERROR] File not found: {encrypted_file}")
            return None

        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()

        print("[*] Encrypted file read successfully")
        print(f"[*] File size: {len(encrypted_data)} bytes")

        # Check for OpenSSL "Salted__" header
        if encrypted_data[:8] != b'Salted__':
            print("[WARNING] File does not have 'Salted__' header")
            print("[*] Attempting decryption anyway...")
        else:
            print("[+] OpenSSL 'Salted__' header detected")

        # Extract salt (8 bytes after "Salted__")
        salt = encrypted_data[8:16]
        actual_encrypted_data = encrypted_data[16:]

        print(f"[+] Salt extracted: {salt.hex()}")
        print(
            f"[*] Actual encrypted data size: {len(actual_encrypted_data)} bytes")

        # Derive key and IV using EVP_BytesToKey
        password_bytes = password.encode('utf-8')
        # 32 bytes for AES-256, 16 for IV
        key, iv = evp_bytes_to_key(password_bytes, salt, 32, 16)

        print(f"[+] Key derived: {key.hex()}")
        print(f"[+] IV derived: {iv.hex()}")

        # Decrypt using AES-256-CBC
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            print("\n[ERROR] cryptography library not installed")
            print("[*] Please install it using: pip install cryptography")
            return None

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(
            actual_encrypted_data) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = decrypted_data[-1]
        if 0 < pad_len <= 16:
            decrypted_data = decrypted_data[:-pad_len]

        print("[+] Decryption successful!")

        # Try to decode as UTF-8
        try:
            decrypted_text = decrypted_data.decode('utf-8')
            print(f"[+] Decoded as UTF-8\n")
            print("=" * 60)
            print("DECRYPTED CONTENT:")
            print("=" * 60)
            print(decrypted_text)
            print("=" * 60)
        except UnicodeDecodeError:
            print("[*] Could not decode as UTF-8, showing hex representation")
            print(decrypted_data.hex())
            decrypted_text = decrypted_data

        # Save to output file if specified
        if output_file:
            try:
                if isinstance(decrypted_text, str):
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(decrypted_text)
                else:
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_text)
                print(f"\n[+] Decrypted content saved to: {output_file}")
            except Exception as e:
                print(f"[ERROR] Could not save to file: {e}")

        return decrypted_text

    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    # Configuration
    ENCRYPTED_FILE = "encrypted.txt"
    PASSWORD_FILE = "aes_passwrd.txt"
    OUTPUT_FILE = "decrypted.txt"

    # Read password from file
    try:
        with open(PASSWORD_FILE, 'r') as f:
            password = f.read().strip()
        print(f"[+] Password read from {PASSWORD_FILE}")
    except FileNotFoundError:
        print(f"[ERROR] Password file not found: {PASSWORD_FILE}")
        print("[*] Using default password: 123456789")
        password = "123456789"

    print(f"[*] Using password: {password}\n")

    # Decrypt the file
    decrypt_file(ENCRYPTED_FILE, password, OUTPUT_FILE)
