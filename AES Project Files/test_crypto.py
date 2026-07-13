"""
test_crypto.py
Unit tests for the AES encryption engine.
Run: python test_crypto.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from crypto_engine import encrypt_file, decrypt_file


class TestAESEngine(unittest.TestCase):

    def _tmp(self, suffix=""):
        """Return a temp file path (auto-cleaned)."""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        self.addCleanup(os.remove, path)
        return path

    # ── Core round-trip ─────────────────────────────────────────────

    def test_roundtrip_small(self):
        """Encrypt then decrypt small data; content must match."""
        src = self._tmp(".txt")
        enc = self._tmp(".enc")
        dec = self._tmp(".dec")
        original = b"Hello, AES-256! This is a test."
        with open(src, "wb") as f:
            f.write(original)

        encrypt_file(src, enc, "TestPassword123!")
        decrypt_file(enc, dec, "TestPassword123!")

        with open(dec, "rb") as f:
            recovered = f.read()

        self.assertEqual(original, recovered)

    def test_roundtrip_large(self):
        """Encrypt then decrypt 2 MB of random bytes."""
        src = self._tmp(".bin")
        enc = self._tmp(".enc")
        dec = self._tmp(".dec")
        data = os.urandom(2 * 1024 * 1024)
        with open(src, "wb") as f:
            f.write(data)

        encrypt_file(src, enc, "AnotherSecurePass#99")
        decrypt_file(enc, dec, "AnotherSecurePass#99")

        with open(dec, "rb") as f:
            recovered = f.read()

        self.assertEqual(data, recovered)

    def test_roundtrip_empty_file(self):
        """Edge case: empty file should encrypt and decrypt correctly."""
        src = self._tmp(".txt")
        enc = self._tmp(".enc")
        dec = self._tmp(".dec")
        with open(src, "wb") as f:
            pass  # empty

        encrypt_file(src, enc, "EmptyFilePass!")
        decrypt_file(enc, dec, "EmptyFilePass!")

        with open(dec, "rb") as f:
            recovered = f.read()

        self.assertEqual(b"", recovered)

    # ── Security tests ───────────────────────────────────────────────

    def test_wrong_password_raises(self):
        """Decrypting with wrong password must raise ValueError."""
        src = self._tmp(".txt")
        enc = self._tmp(".enc")
        fd, dec = tempfile.mkstemp(".dec")
        os.close(fd)
        with open(src, "wb") as f:
            f.write(b"Secret data")

        encrypt_file(src, enc, "CorrectPassword!")

        with self.assertRaises(ValueError):
            decrypt_file(enc, dec, "WrongPassword!")

        if os.path.exists(dec):
            os.remove(dec)

    def test_different_salts(self):
        """Two encryptions of same file must produce different ciphertext (random salt/IV)."""
        src = self._tmp(".txt")
        enc1 = self._tmp(".enc")
        enc2 = self._tmp(".enc")
        with open(src, "wb") as f:
            f.write(b"Same content, different outputs expected.")

        encrypt_file(src, enc1, "SamePassword!")
        encrypt_file(src, enc2, "SamePassword!")

        with open(enc1, "rb") as f1, open(enc2, "rb") as f2:
            c1, c2 = f1.read(), f2.read()

        self.assertNotEqual(c1, c2, "Ciphertexts must differ due to random IV/salt")

    def test_corrupted_file_raises(self):
        """Decrypting garbage data must raise ValueError."""
        bad = self._tmp(".enc")
        fd, dec = tempfile.mkstemp(".dec")
        os.close(fd)
        with open(bad, "wb") as f:
            f.write(os.urandom(256))

        with self.assertRaises(ValueError):
            decrypt_file(bad, dec, "AnyPassword!")

        if os.path.exists(dec):
            os.remove(dec)

    def test_wrong_magic_header_raises(self):
        """File missing magic header must raise ValueError."""
        bad = self._tmp(".enc")
        fd, dec = tempfile.mkstemp(".dec")
        os.close(fd)
        # Write valid-looking size but wrong magic
        with open(bad, "wb") as f:
            f.write(b"WRONGHDR" + os.urandom(200))

        with self.assertRaises(ValueError):
            decrypt_file(bad, dec, "AnyPassword!")

        if os.path.exists(dec):
            os.remove(dec)

    # ── Progress callback ────────────────────────────────────────────

    def test_progress_callback_called(self):
        """Progress callback should be invoked during encryption."""
        src = self._tmp(".txt")
        enc = self._tmp(".enc")
        dec = self._tmp(".dec")
        with open(src, "wb") as f:
            f.write(os.urandom(512 * 1024))  # 512 KB

        progress_vals = []
        encrypt_file(src, enc, "ProgressTest!", progress_callback=progress_vals.append)
        decrypt_file(enc, dec, "ProgressTest!")

        # Should have seen progress updates
        self.assertGreater(len(progress_vals), 0)
        self.assertEqual(progress_vals[-1], 100)


if __name__ == "__main__":
    print("=" * 60)
    print("  AES Encryption Engine — Unit Tests")
    # print("  Student: Saud Hussain  |  Roll: 0000948599")
    print("=" * 60)
    unittest.main(verbosity=2)
