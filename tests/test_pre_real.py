"""Tests for X25519 Proxy Re-Encryption backend.

These tests verify the real X25519-based PRE backend provides actual
cryptographic security while matching the interface contract.
"""

from datetime import datetime, timedelta

import pytest

from our_crypto.pre import (
    PREBackend,
    PRECiphertext,
    PREDecryptionError,
    PREReEncryptionError,
)
from our_crypto.pre_real import X25519PREBackend


class TestX25519PREBackendKeyGeneration:
    """Tests for X25519 key pair generation."""

    @pytest.fixture
    def backend(self) -> X25519PREBackend:
        return X25519PREBackend()

    def test_implements_interface(self, backend: X25519PREBackend) -> None:
        """X25519PREBackend implements PREBackend."""
        assert isinstance(backend, PREBackend)

    def test_generate_keypair(self, backend: X25519PREBackend) -> None:
        """Key pair generation produces 32-byte X25519 keys."""
        keypair = backend.generate_keypair(b"alice")

        assert keypair.key_id == b"alice"
        assert len(keypair.public_key.key_bytes) == 32
        assert len(keypair.private_key.key_bytes) == 32
        assert keypair.public_key.key_id == keypair.private_key.key_id

    def test_generate_unique_keypairs(self, backend: X25519PREBackend) -> None:
        """Each generation produces unique key material."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        assert alice.public_key.key_bytes != bob.public_key.key_bytes
        assert alice.private_key.key_bytes != bob.private_key.key_bytes

    def test_keypair_metadata(self, backend: X25519PREBackend) -> None:
        """Key pairs include algorithm metadata."""
        keypair = backend.generate_keypair(b"alice")
        assert keypair.public_key.metadata["algorithm"] == "x25519-ecies"


class TestX25519PREBackendEncryptDecrypt:
    """Tests for ECIES encryption and decryption."""

    @pytest.fixture
    def backend(self) -> X25519PREBackend:
        return X25519PREBackend()

    def test_encrypt_decrypt_roundtrip(self, backend: X25519PREBackend) -> None:
        """Basic encrypt/decrypt roundtrip with real crypto."""
        alice = backend.generate_keypair(b"alice")
        plaintext = b"Hello, this is a secret message!"

        ciphertext = backend.encrypt(plaintext, alice.public_key)
        decrypted = backend.decrypt(ciphertext, alice.private_key)

        assert decrypted == plaintext

    def test_encrypt_creates_proper_ciphertext(self, backend: X25519PREBackend) -> None:
        """Encryption produces properly structured ciphertext."""
        alice = backend.generate_keypair(b"alice")
        ciphertext = backend.encrypt(b"data", alice.public_key, metadata={"type": "belief"})

        assert ciphertext.recipient_id == b"alice"
        assert not ciphertext.is_reencrypted
        assert ciphertext.metadata["type"] == "belief"
        assert len(ciphertext.ciphertext_id) == 16
        # encrypted_data = eph_pk(32) + nonce(12) + aes_gcm(data + 16-byte tag)
        assert len(ciphertext.encrypted_data) >= 32 + 12 + 16

    def test_ciphertext_is_nondeterministic(self, backend: X25519PREBackend) -> None:
        """Same plaintext + key produces different ciphertexts (ephemeral keys)."""
        alice = backend.generate_keypair(b"alice")
        ct1 = backend.encrypt(b"same data", alice.public_key)
        ct2 = backend.encrypt(b"same data", alice.public_key)

        assert ct1.encrypted_data != ct2.encrypted_data

    def test_decrypt_wrong_key_fails(self, backend: X25519PREBackend) -> None:
        """Decryption with wrong key raises PREDecryptionError."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        ciphertext = backend.encrypt(b"secret", alice.public_key)

        with pytest.raises(PREDecryptionError):
            backend.decrypt(ciphertext, bob.private_key)

    def test_decrypt_tampered_ciphertext_fails(self, backend: X25519PREBackend) -> None:
        """Tampered ciphertext fails AES-GCM authentication."""
        alice = backend.generate_keypair(b"alice")
        ciphertext = backend.encrypt(b"secret data", alice.public_key)

        # Tamper with the encrypted data (flip a byte in the GCM ciphertext)
        data = bytearray(ciphertext.encrypted_data)
        data[-1] ^= 0xFF  # Flip last byte (in auth tag)
        tampered = PRECiphertext(
            ciphertext_id=ciphertext.ciphertext_id,
            encrypted_data=bytes(data),
            recipient_id=ciphertext.recipient_id,
        )

        with pytest.raises(PREDecryptionError):
            backend.decrypt(tampered, alice.private_key)

    def test_large_plaintext(self, backend: X25519PREBackend) -> None:
        """Encryption of larger data works correctly."""
        alice = backend.generate_keypair(b"alice")
        plaintext = b"x" * 10000

        ciphertext = backend.encrypt(plaintext, alice.public_key)
        decrypted = backend.decrypt(ciphertext, alice.private_key)

        assert decrypted == plaintext

    def test_empty_plaintext(self, backend: X25519PREBackend) -> None:
        """Encryption of empty data works (AES-GCM supports this)."""
        alice = backend.generate_keypair(b"alice")

        ciphertext = backend.encrypt(b"", alice.public_key)
        decrypted = backend.decrypt(ciphertext, alice.private_key)

        assert decrypted == b""

    def test_ciphertext_too_short_fails(self, backend: X25519PREBackend) -> None:
        """Too-short ciphertext raises decryption error."""
        alice = backend.generate_keypair(b"alice")
        short_ct = PRECiphertext(
            ciphertext_id=b"x" * 16,
            encrypted_data=b"short",
            recipient_id=b"alice",
        )

        with pytest.raises(PREDecryptionError):
            backend.decrypt(short_ct, alice.private_key)


class TestX25519PREBackendReEncryption:
    """Tests for trusted-proxy re-encryption."""

    @pytest.fixture
    def backend(self) -> X25519PREBackend:
        return X25519PREBackend()

    def test_re_encrypt_basic(self, backend: X25519PREBackend) -> None:
        """Basic re-encryption: Alice -> proxy -> Bob."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")
        plaintext = b"Shared secret for federation"

        # Alice encrypts
        ciphertext = backend.encrypt(plaintext, alice.public_key)

        # Alice generates rekey for Bob
        rekey = backend.generate_rekey(alice.private_key, bob.public_key)

        # Proxy re-encrypts
        re_encrypted = backend.re_encrypt(ciphertext, rekey)

        # Verify re-encrypted properties
        assert re_encrypted.recipient_id == b"bob"
        assert re_encrypted.is_reencrypted
        assert re_encrypted.original_recipient_id == b"alice"

        # Bob decrypts
        decrypted = backend.decrypt(re_encrypted, bob.private_key)
        assert decrypted == plaintext

    def test_re_encrypt_chain(self, backend: X25519PREBackend) -> None:
        """Multi-hop re-encryption: Alice -> Bob -> Carol."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")
        carol = backend.generate_keypair(b"carol")
        plaintext = b"Multi-hop federation data"

        ct_alice = backend.encrypt(plaintext, alice.public_key)

        rekey_ab = backend.generate_rekey(alice.private_key, bob.public_key)
        ct_bob = backend.re_encrypt(ct_alice, rekey_ab)

        rekey_bc = backend.generate_rekey(bob.private_key, carol.public_key)
        ct_carol = backend.re_encrypt(ct_bob, rekey_bc)

        decrypted = backend.decrypt(ct_carol, carol.private_key)
        assert decrypted == plaintext

    def test_re_encrypt_wrong_rekey_fails(self, backend: X25519PREBackend) -> None:
        """Re-encryption with mismatched rekey fails."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")
        carol = backend.generate_keypair(b"carol")

        ciphertext = backend.encrypt(b"secret", alice.public_key)
        wrong_rekey = backend.generate_rekey(bob.private_key, carol.public_key)

        with pytest.raises(PREReEncryptionError):
            backend.re_encrypt(ciphertext, wrong_rekey)

    def test_re_encrypt_expired_rekey_fails(self, backend: X25519PREBackend) -> None:
        """Re-encryption with expired rekey fails."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        ciphertext = backend.encrypt(b"secret", alice.public_key)
        expired = datetime.now() - timedelta(hours=1)
        rekey = backend.generate_rekey(alice.private_key, bob.public_key, expires_at=expired)

        with pytest.raises(PREReEncryptionError):
            backend.re_encrypt(ciphertext, rekey)

    def test_generate_rekey_properties(self, backend: X25519PREBackend) -> None:
        """Re-encryption key has correct properties."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        rekey = backend.generate_rekey(alice.private_key, bob.public_key)

        assert rekey.delegator_id == b"alice"
        assert rekey.delegatee_id == b"bob"
        assert len(rekey.key_bytes) == 32
        assert not rekey.is_expired

    def test_generate_rekey_with_expiration(self, backend: X25519PREBackend) -> None:
        """Re-encryption key respects expiration."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        expires = datetime.now() + timedelta(hours=24)
        rekey = backend.generate_rekey(alice.private_key, bob.public_key, expires_at=expires)

        assert rekey.expires_at == expires
        assert not rekey.is_expired

    def test_unidirectional_delegation(self, backend: X25519PREBackend) -> None:
        """Re-encryption is unidirectional: A->B rekey can't re-encrypt B's data."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        rekey_ab = backend.generate_rekey(alice.private_key, bob.public_key)

        alice_ct = backend.encrypt(b"alice data", alice.public_key)
        bob_ct = backend.encrypt(b"bob data", bob.public_key)

        # Alice's data can flow to Bob
        re_ct = backend.re_encrypt(alice_ct, rekey_ab)
        assert backend.decrypt(re_ct, bob.private_key) == b"alice data"

        # Bob's data cannot use Alice->Bob rekey
        with pytest.raises(PREReEncryptionError):
            backend.re_encrypt(bob_ct, rekey_ab)


class TestX25519PREBackendVerification:
    """Tests for ciphertext verification."""

    @pytest.fixture
    def backend(self) -> X25519PREBackend:
        return X25519PREBackend()

    def test_verify_valid_ciphertext(self, backend: X25519PREBackend) -> None:
        """Valid ciphertext passes verification (incl. auth tag check)."""
        alice = backend.generate_keypair(b"alice")
        ciphertext = backend.encrypt(b"data", alice.public_key)
        assert backend.verify_ciphertext(ciphertext)

    def test_verify_unknown_ciphertext_structure(self, backend: X25519PREBackend) -> None:
        """Unknown ciphertext with valid structure passes structural check."""
        fake_ct = PRECiphertext(
            ciphertext_id=b"unknown" + b"\x00" * 9,
            encrypted_data=b"\x00" * 100,  # Long enough to pass structure check
            recipient_id=b"alice",
        )
        # Passes structural check but no auth tag verification (no DEK cached)
        assert backend.verify_ciphertext(fake_ct)

    def test_verify_too_short_ciphertext(self, backend: X25519PREBackend) -> None:
        """Too-short ciphertext fails verification."""
        short_ct = PRECiphertext(
            ciphertext_id=b"x" * 16,
            encrypted_data=b"short",
            recipient_id=b"alice",
        )
        assert not backend.verify_ciphertext(short_ct)

    def test_verify_tampered_ciphertext(self, backend: X25519PREBackend) -> None:
        """Tampered ciphertext fails auth tag verification."""
        alice = backend.generate_keypair(b"alice")
        ciphertext = backend.encrypt(b"data", alice.public_key)

        # Tamper
        data = bytearray(ciphertext.encrypted_data)
        data[-1] ^= 0xFF
        tampered = PRECiphertext(
            ciphertext_id=ciphertext.ciphertext_id,
            encrypted_data=bytes(data),
            recipient_id=ciphertext.recipient_id,
        )
        assert not backend.verify_ciphertext(tampered)


class TestX25519PREBackendFederation:
    """Tests simulating federation scenarios with real crypto."""

    @pytest.fixture
    def backend(self) -> X25519PREBackend:
        return X25519PREBackend()

    def test_belief_sharing(self, backend: X25519PREBackend) -> None:
        """Share encrypted beliefs between federation instances."""
        instance_a = backend.generate_keypair(b"instance-a")
        instance_b = backend.generate_keypair(b"instance-b")

        belief_data = b'{"content": "The sky is blue", "confidence": 0.95}'
        encrypted = backend.encrypt(belief_data, instance_a.public_key)

        rekey = backend.generate_rekey(instance_a.private_key, instance_b.public_key)
        shared = backend.re_encrypt(encrypted, rekey)

        received = backend.decrypt(shared, instance_b.private_key)
        assert received == belief_data

    def test_multi_recipient_sharing(self, backend: X25519PREBackend) -> None:
        """Share same data with multiple recipients."""
        source = backend.generate_keypair(b"source")
        dest1 = backend.generate_keypair(b"dest1")
        dest2 = backend.generate_keypair(b"dest2")
        dest3 = backend.generate_keypair(b"dest3")

        data = b"Federation knowledge graph update"
        encrypted = backend.encrypt(data, source.public_key)

        for _dest, dest_kp in [(b"dest1", dest1), (b"dest2", dest2), (b"dest3", dest3)]:
            rekey = backend.generate_rekey(source.private_key, dest_kp.public_key)
            shared = backend.re_encrypt(encrypted, rekey)
            assert backend.decrypt(shared, dest_kp.private_key) == data

    def test_reencrypted_ciphertext_differs(self, backend: X25519PREBackend) -> None:
        """Re-encrypted ciphertexts use fresh ephemeral keys (non-deterministic)."""
        alice = backend.generate_keypair(b"alice")
        bob = backend.generate_keypair(b"bob")

        ct = backend.encrypt(b"data", alice.public_key)
        rekey = backend.generate_rekey(alice.private_key, bob.public_key)

        re1 = backend.re_encrypt(ct, rekey)
        re2 = backend.re_encrypt(ct, rekey)

        # Both decrypt to same plaintext
        assert backend.decrypt(re1, bob.private_key) == b"data"
        assert backend.decrypt(re2, bob.private_key) == b"data"

        # But ciphertexts are different (different ephemeral keys)
        assert re1.encrypted_data != re2.encrypted_data
