"""Tests for shared cryptographic primitives.

Includes RFC 5869 HKDF test vectors for validation.
"""

import pytest
from cryptography.exceptions import InvalidTag

from our_crypto._primitives import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ed25519_generate,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    hkdf_expand,
    hkdf_extract,
    secure_hash,
    x25519_dh,
    x25519_generate,
)


class TestHKDF:
    """Tests for HKDF functions including RFC 5869 test vectors."""

    def test_hkdf_extract_rfc5869_test_case_1(self):
        """RFC 5869 Test Case 1: Basic extraction."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        expected_prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

        prk = hkdf_extract(salt, ikm)
        assert prk == expected_prk

    def test_hkdf_expand_rfc5869_test_case_1(self):
        """RFC 5869 Test Case 1: Basic expansion."""
        prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )

        okm = hkdf_expand(prk, info, length=42)
        assert okm == expected_okm

    def test_hkdf_extract_rfc5869_test_case_2(self):
        """RFC 5869 Test Case 2: Longer inputs."""
        ikm = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f"
        )
        salt = bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )
        expected_prk = bytes.fromhex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

        prk = hkdf_extract(salt, ikm)
        assert prk == expected_prk

    def test_hkdf_expand_rfc5869_test_case_2(self):
        """RFC 5869 Test Case 2: Longer expansion."""
        prk = bytes.fromhex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        info = bytes.fromhex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )
        expected_okm = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )

        okm = hkdf_expand(prk, info, length=82)
        assert okm == expected_okm

    def test_hkdf_extract_rfc5869_test_case_3(self):
        """RFC 5869 Test Case 3: No salt."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        expected_prk = bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

        prk = hkdf_extract(None, ikm)
        assert prk == expected_prk

    def test_hkdf_expand_rfc5869_test_case_3(self):
        """RFC 5869 Test Case 3: No info."""
        prk = bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        expected_okm = bytes.fromhex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )

        okm = hkdf_expand(prk, b"", length=42)
        assert okm == expected_okm

    def test_hkdf_derive_roundtrip(self):
        """Test that hkdf_derive produces consistent output."""
        ikm = b"input keying material"
        info = b"application context"

        result1 = hkdf_derive(ikm, info, length=32)
        result2 = hkdf_derive(ikm, info, length=32)
        assert result1 == result2
        assert len(result1) == 32

    def test_hkdf_derive_different_info_different_output(self):
        """Different info produces different output."""
        ikm = b"same input"
        result1 = hkdf_derive(ikm, b"context-a")
        result2 = hkdf_derive(ikm, b"context-b")
        assert result1 != result2

    def test_hkdf_derive_variable_length(self):
        """Test deriving different lengths."""
        ikm = b"keying material"
        info = b"test"

        result_16 = hkdf_derive(ikm, info, length=16)
        result_32 = hkdf_derive(ikm, info, length=32)
        result_64 = hkdf_derive(ikm, info, length=64)

        assert len(result_16) == 16
        assert len(result_32) == 32
        assert len(result_64) == 64


class TestAESGCM:
    """Tests for AES-256-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Basic encrypt/decrypt roundtrip."""
        key = b"\x42" * 32
        plaintext = b"Hello, AES-GCM!"

        ciphertext, nonce = aes_gcm_encrypt(key, plaintext)
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad(self):
        """Encrypt/decrypt with associated data."""
        key = b"\x42" * 32
        plaintext = b"authenticated message"
        aad = b"header data"

        ciphertext, nonce = aes_gcm_encrypt(key, plaintext, aad=aad)
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad=aad)

        assert decrypted == plaintext

    def test_wrong_aad_fails(self):
        """Wrong AAD causes authentication failure."""
        key = b"\x42" * 32
        plaintext = b"authenticated message"

        ciphertext, nonce = aes_gcm_encrypt(key, plaintext, aad=b"correct")

        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key, nonce, ciphertext, aad=b"wrong")

    def test_wrong_key_fails(self):
        """Wrong key causes decryption failure."""
        key1 = b"\x42" * 32
        key2 = b"\x43" * 32
        plaintext = b"secret"

        ciphertext, nonce = aes_gcm_encrypt(key1, plaintext)

        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(key2, nonce, ciphertext)

    def test_nondeterministic_encryption(self):
        """Same plaintext + key produces different ciphertexts (random nonce)."""
        key = b"\x42" * 32
        plaintext = b"same message"

        ct1, nonce1 = aes_gcm_encrypt(key, plaintext)
        ct2, nonce2 = aes_gcm_encrypt(key, plaintext)

        assert nonce1 != nonce2
        assert ct1 != ct2

    def test_empty_plaintext(self):
        """Encrypt/decrypt empty data (GCM supports this)."""
        key = b"\x42" * 32
        ciphertext, nonce = aes_gcm_encrypt(key, b"")
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Encrypt/decrypt large data."""
        key = b"\x42" * 32
        plaintext = b"x" * 100_000

        ciphertext, nonce = aes_gcm_encrypt(key, plaintext)
        decrypted = aes_gcm_decrypt(key, nonce, ciphertext)

        assert decrypted == plaintext

    def test_invalid_key_size(self):
        """Invalid key size raises ValueError."""
        with pytest.raises(ValueError, match="32 bytes"):
            aes_gcm_encrypt(b"short", b"data")

        with pytest.raises(ValueError, match="32 bytes"):
            aes_gcm_decrypt(b"short", b"\x00" * 12, b"data")


class TestX25519:
    """Tests for X25519 key generation and DH."""

    def test_generate_keypair(self):
        """Generate produces 32-byte keys."""
        private, public = x25519_generate()
        assert len(private) == 32
        assert len(public) == 32

    def test_generate_unique_keys(self):
        """Each generation produces unique keys."""
        priv1, pub1 = x25519_generate()
        priv2, pub2 = x25519_generate()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_dh_shared_secret(self):
        """DH produces the same shared secret for both parties."""
        priv_a, pub_a = x25519_generate()
        priv_b, pub_b = x25519_generate()

        shared_ab = x25519_dh(priv_a, pub_b)
        shared_ba = x25519_dh(priv_b, pub_a)

        assert shared_ab == shared_ba
        assert len(shared_ab) == 32

    def test_dh_different_pairs_different_secrets(self):
        """Different key pairs produce different shared secrets."""
        priv_a, pub_a = x25519_generate()
        priv_b, pub_b = x25519_generate()
        priv_c, pub_c = x25519_generate()

        shared_ab = x25519_dh(priv_a, pub_b)
        shared_ac = x25519_dh(priv_a, pub_c)

        assert shared_ab != shared_ac


class TestEd25519:
    """Tests for Ed25519 signing and verification."""

    def test_generate_keypair(self):
        """Generate produces 32-byte keys."""
        private, public = ed25519_generate()
        assert len(private) == 32
        assert len(public) == 32

    def test_sign_verify_roundtrip(self):
        """Signing and verifying produces valid result."""
        private, public = ed25519_generate()
        message = b"test message"

        signature = ed25519_sign(private, message)
        assert len(signature) == 64
        assert ed25519_verify(public, message, signature)

    def test_wrong_message_fails(self):
        """Verification fails for wrong message."""
        private, public = ed25519_generate()
        signature = ed25519_sign(private, b"original")
        assert not ed25519_verify(public, b"tampered", signature)

    def test_wrong_key_fails(self):
        """Verification fails with wrong public key."""
        priv1, pub1 = ed25519_generate()
        _priv2, pub2 = ed25519_generate()

        signature = ed25519_sign(priv1, b"message")
        assert ed25519_verify(pub1, b"message", signature)
        assert not ed25519_verify(pub2, b"message", signature)

    def test_tampered_signature_fails(self):
        """Verification fails with tampered signature."""
        private, public = ed25519_generate()
        signature = ed25519_sign(private, b"message")

        tampered = bytearray(signature)
        tampered[0] ^= 0xFF
        assert not ed25519_verify(public, b"message", bytes(tampered))


class TestSecureHash:
    """Tests for labeled SHA-256 hashing."""

    def test_deterministic(self):
        """Same input produces same hash."""
        h1 = secure_hash(b"data", b"label")
        h2 = secure_hash(b"data", b"label")
        assert h1 == h2
        assert len(h1) == 32

    def test_different_data_different_hash(self):
        """Different data produces different hash."""
        h1 = secure_hash(b"data1", b"label")
        h2 = secure_hash(b"data2", b"label")
        assert h1 != h2

    def test_different_label_different_hash(self):
        """Different labels produce different hash (domain separation)."""
        h1 = secure_hash(b"data", b"label-a")
        h2 = secure_hash(b"data", b"label-b")
        assert h1 != h2

    def test_no_label(self):
        """Works without a label."""
        h = secure_hash(b"data")
        assert len(h) == 32
