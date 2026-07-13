"""
crypto_engine.py
AES-256-CBC Encryption/Decryption Engine
Uses PBKDF2 for key derivation from password.
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


MAGIC = b"AESENC_V1"  # File header to identify encrypted files
SALT_SIZE = 16         # 128-bit salt
IV_SIZE = 16           # 128-bit IV (AES block size)
KEY_SIZE = 32          # 256-bit key
PBKDF2_ITER = 200_000  # NIST-recommended iterations


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=PBKDF2_ITER,
        dklen=KEY_SIZE,
    )


def encrypt_file(input_path: str, output_path: str, password: str,
                 progress_callback=None) -> dict:
    """
    Encrypt a file with AES-256-CBC.
    Output format: MAGIC (9) + SALT (16) + IV (16) + CIPHERTEXT
    Returns dict with status and metadata.
    """
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    file_size = os.path.getsize(input_path)
    bytes_processed = 0

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        # Write header
        f_out.write(MAGIC)
        f_out.write(salt)
        f_out.write(iv)

        chunk_size = 64 * 1024  # 64 KB chunks
        prev_chunk = None

        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                # Last chunk — apply padding
                if prev_chunk is not None:
                    f_out.write(cipher.encrypt(pad(prev_chunk, AES.block_size)))
                else:
                    f_out.write(cipher.encrypt(pad(b"", AES.block_size)))
                break

            if prev_chunk is not None:
                f_out.write(cipher.encrypt(prev_chunk))

            prev_chunk = chunk
            bytes_processed += len(chunk)

            if progress_callback and file_size > 0:
                progress_callback(int(bytes_processed / file_size * 100))

    return {
        "status": "success",
        "original_size": file_size,
        "output_path": output_path,
    }


def decrypt_file(input_path: str, output_path: str, password: str,
                 progress_callback=None) -> dict:
    """
    Decrypt an AES-256-CBC encrypted file.
    Raises ValueError on wrong password or corrupted file.
    """
    with open(input_path, "rb") as f_in:
        # Read and verify header
        magic = f_in.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a valid encrypted file or file is corrupted.")

        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(IV_SIZE)

        if len(salt) < SALT_SIZE or len(iv) < IV_SIZE:
            raise ValueError("Encrypted file is truncated or corrupted.")

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        ciphertext = f_in.read()

    if not ciphertext:
        raise ValueError("No encrypted data found in file.")

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError):
        raise ValueError("Decryption failed. Wrong password or corrupted file.")

    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)

    if progress_callback:
        progress_callback(100)

    return {
        "status": "success",
        "decrypted_size": len(plaintext),
        "output_path": output_path,
    }
