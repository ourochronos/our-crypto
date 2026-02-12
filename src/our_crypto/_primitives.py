"""Shared cryptographic primitives for real backends.

Thin wrappers around the `cryptography` library to provide consistent
interfaces for HKDF, AES-GCM, X25519, and Ed25519 across all backends.

All functions in this module use the PyCA `cryptography` library (audited,
well-maintained) and operate on raw bytes for composability.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

# AES-GCM nonce size (96 bits per NIST recommendation)
_AES_GCM_NONCE_SIZE = 12
# AES-256 key size
_AES_KEY_SIZE = 32
# HKDF default hash
_HKDF_HASH = hashes.SHA256()
_HKDF_HASH_LEN = 32


def hkdf_derive(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    """Derive key material using HKDF (extract-then-expand).

    Args:
        ikm: Input keying material
        info: Context and application specific information
        length: Length of output keying material in bytes
        salt: Optional salt value (a non-secret random value)

    Returns:
        Derived key material of the specified length
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    """HKDF-Extract: extract a pseudorandom key from input keying material.

    This is the extract step of HKDF per RFC 5869 Section 2.2.
    PRK = HMAC-Hash(salt, IKM)

    Args:
        salt: Optional salt value (if None, uses zero-filled string of HashLen)
        ikm: Input keying material

    Returns:
        Pseudorandom key (PRK) of HashLen bytes
    """
    import hmac as _hmac

    if salt is None:
        salt = b"\x00" * _HKDF_HASH_LEN
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand: expand a pseudorandom key to the desired length.

    This is the expand step of HKDF per RFC 5869 Section 2.3.

    Args:
        prk: Pseudorandom key (at least HashLen bytes)
        info: Context and application specific information
        length: Length of output keying material in bytes (max 255*HashLen)

    Returns:
        Output keying material of the specified length
    """
    hkdf_exp = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    )
    return hkdf_exp.derive(prk)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt using AES-256-GCM.

    Args:
        key: 32-byte AES-256 key
        plaintext: Data to encrypt
        aad: Optional additional authenticated data

    Returns:
        Tuple of (ciphertext_with_tag, nonce). The ciphertext includes the
        16-byte authentication tag appended by the library.
    """
    if len(key) != _AES_KEY_SIZE:
        raise ValueError(f"AES-256 key must be {_AES_KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(_AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt using AES-256-GCM.

    Args:
        key: 32-byte AES-256 key
        nonce: 12-byte nonce used during encryption
        ciphertext: Ciphertext with appended authentication tag
        aad: Optional additional authenticated data (must match encryption)

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    if len(key) != _AES_KEY_SIZE:
        raise ValueError(f"AES-256 key must be {_AES_KEY_SIZE} bytes, got {len(key)}")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def x25519_generate() -> tuple[bytes, bytes]:
    """Generate an X25519 key pair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes), both 32 bytes.
    """
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def x25519_dh(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """Perform X25519 Diffie-Hellman key exchange.

    Args:
        private_bytes: 32-byte private key
        public_bytes: 32-byte public key of the other party

    Returns:
        32-byte shared secret
    """
    private_key = X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = X25519PublicKey.from_public_bytes(public_bytes)
    return private_key.exchange(public_key)


def ed25519_generate() -> tuple[bytes, bytes]:
    """Generate an Ed25519 signing key pair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes).
        Private key is 32 bytes, public key is 32 bytes.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def ed25519_sign(private_bytes: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519.

    Args:
        private_bytes: 32-byte private key
        message: Message to sign

    Returns:
        64-byte signature
    """
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.sign(message)


def ed25519_verify(public_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_bytes: 32-byte public key
        message: Original message
        signature: 64-byte signature to verify

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def secure_hash(data: bytes, label: bytes = b"") -> bytes:
    """Compute a labeled SHA-256 hash.

    Args:
        data: Data to hash
        label: Optional domain separation label

    Returns:
        32-byte hash
    """
    h = hashlib.sha256()
    if label:
        h.update(label)
        h.update(b"\x00")  # separator
    h.update(data)
    return h.digest()
