"""X25519 Proxy Re-Encryption Backend.

ECIES hybrid encryption (X25519 DH + HKDF + AES-256-GCM) with trusted-proxy
re-encryption. Provides real cryptographic security for federation sharing.

Security model:
    Trusted proxy — the backend instance holds data encryption keys (DEKs) in
    memory to enable re-encryption without the delegator's private key. This is
    acceptable for semi-trusted federation relays where the proxy runs in a
    controlled environment. True blind PRE requires pairing-based crypto (no
    maintained Python library exists) — documented as upgrade path.

Scheme:
    - generate_keypair: X25519 keypair (32-byte private, 32-byte public)
    - encrypt: Ephemeral X25519 DH -> HKDF -> AES-256-GCM. DEK cached by backend.
    - decrypt: Recover ephemeral pk from ciphertext -> DH -> HKDF -> AES-GCM decrypt
    - generate_rekey: DH(delegator_sk, delegatee_pk) -> HKDF -> 32-byte transform key
    - re_encrypt: Recover DEK from cache, decrypt, re-encrypt via ECIES for delegatee
    - verify_ciphertext: Structure validation + auth tag check if DEK available

Reference: our-privacy/src/our_privacy/encryption.py (same ECIES pattern)
"""

from __future__ import annotations

import secrets as crypto_secrets
from datetime import datetime
from typing import Any

from our_crypto._primitives import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_derive,
    x25519_dh,
    x25519_generate,
)
from our_crypto.pre import (
    PREBackend,
    PRECiphertext,
    PREDecryptionError,
    PREEncryptionError,
    PREKeyPair,
    PREPrivateKey,
    PREPublicKey,
    PREReEncryptionError,
    ReEncryptionKey,
)

# Domain separation labels for HKDF derivations
_LABEL_DEK = b"our-crypto-pre-x25519-dek-v1"
_LABEL_REKEY = b"our-crypto-pre-x25519-rekey-v1"


class X25519PREBackend(PREBackend):
    """X25519-based Proxy Re-Encryption backend.

    Uses ECIES hybrid encryption (X25519 DH + HKDF + AES-256-GCM) with
    trusted-proxy re-encryption. Provides real cryptographic security.

    Ciphertext format (stored in encrypted_data):
        ephemeral_pubkey (32 bytes) || nonce (12 bytes) || aes_gcm_ciphertext (variable)

    The AES-GCM ciphertext includes the 16-byte auth tag appended by the library.

    Trust model:
        The backend instance maintains DEKs in memory for each ciphertext it
        has encrypted. This enables re-encryption without the delegator's
        private key. The proxy temporarily holds DEKs — but NOT private keys.
    """

    _EPHEMERAL_PK_SIZE = 32
    _NONCE_SIZE = 12
    _MIN_CIPHERTEXT_SIZE = 32 + 12 + 16  # eph_pk + nonce + min GCM (tag only)

    def __init__(self) -> None:
        """Initialize the X25519 PRE backend."""
        # DEK cache: ciphertext_id -> (dek, recipient_id)
        self._deks: dict[bytes, tuple[bytes, bytes]] = {}
        # Public key registry: key_id -> public_key_bytes
        self._public_keys: dict[bytes, bytes] = {}

    def generate_keypair(self, key_id: bytes) -> PREKeyPair:
        """Generate an X25519 key pair."""
        private_bytes, public_bytes = x25519_generate()
        now = datetime.now()

        # Register public key for re-encryption lookups
        self._public_keys[key_id] = public_bytes

        public_key = PREPublicKey(
            key_id=key_id,
            key_bytes=public_bytes,
            created_at=now,
            metadata={"algorithm": "x25519-ecies", "version": "1.0"},
        )
        private_key = PREPrivateKey(
            key_id=key_id,
            key_bytes=private_bytes,
            created_at=now,
            metadata={"algorithm": "x25519-ecies", "version": "1.0"},
        )
        return PREKeyPair(public_key=public_key, private_key=private_key)

    def generate_rekey(
        self,
        delegator_private_key: PREPrivateKey,
        delegatee_public_key: PREPublicKey,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReEncryptionKey:
        """Generate a re-encryption key via DH(delegator_sk, delegatee_pk) -> HKDF.

        Also registers the delegatee's public key so re_encrypt can
        create fresh ECIES ciphertexts for the delegatee.
        """
        # Register delegatee's public key
        self._public_keys[delegatee_public_key.key_id] = delegatee_public_key.key_bytes

        try:
            shared_secret = x25519_dh(delegator_private_key.key_bytes, delegatee_public_key.key_bytes)
        except Exception as e:
            raise PREEncryptionError(f"Failed to compute DH for rekey: {e}") from e

        info = _LABEL_REKEY + delegator_private_key.key_id + delegatee_public_key.key_id
        rekey_bytes = hkdf_derive(shared_secret, info, length=32)

        return ReEncryptionKey(
            rekey_id=crypto_secrets.token_bytes(16),
            delegator_id=delegator_private_key.key_id,
            delegatee_id=delegatee_public_key.key_id,
            key_bytes=rekey_bytes,
            created_at=datetime.now(),
            expires_at=expires_at,
            metadata=metadata or {},
        )

    def encrypt(
        self,
        plaintext: bytes,
        recipient_public_key: PREPublicKey,
        metadata: dict[str, Any] | None = None,
    ) -> PRECiphertext:
        """Encrypt using ephemeral X25519 DH -> HKDF -> AES-256-GCM.

        The DEK is cached in the backend to enable future re-encryption.
        """
        # Register public key
        self._public_keys[recipient_public_key.key_id] = recipient_public_key.key_bytes

        try:
            # Generate ephemeral keypair
            eph_private, eph_public = x25519_generate()

            # DH with recipient's public key
            shared_secret = x25519_dh(eph_private, recipient_public_key.key_bytes)

            # Derive data encryption key
            dek = hkdf_derive(shared_secret, _LABEL_DEK + recipient_public_key.key_id, length=32)

            # Encrypt with AES-256-GCM
            ciphertext_data, nonce = aes_gcm_encrypt(dek, plaintext)

            # Pack: ephemeral_pk || nonce || ciphertext_with_tag
            encrypted_data = eph_public + nonce + ciphertext_data

        except PREEncryptionError:
            raise
        except Exception as e:
            raise PREEncryptionError(f"Encryption failed: {e}") from e

        ciphertext_id = crypto_secrets.token_bytes(16)

        # Cache DEK for re-encryption (trusted proxy state)
        self._deks[ciphertext_id] = (dek, recipient_public_key.key_id)

        return PRECiphertext(
            ciphertext_id=ciphertext_id,
            encrypted_data=encrypted_data,
            recipient_id=recipient_public_key.key_id,
            is_reencrypted=False,
            original_recipient_id=None,
            created_at=datetime.now(),
            metadata=metadata or {},
        )

    def decrypt(
        self,
        ciphertext: PRECiphertext,
        recipient_private_key: PREPrivateKey,
    ) -> bytes:
        """Decrypt by recovering ephemeral pk -> DH -> HKDF -> AES-GCM."""
        if ciphertext.recipient_id != recipient_private_key.key_id:
            raise PREDecryptionError(
                f"Key mismatch: ciphertext for {ciphertext.recipient_id.hex()}, "
                f"but got key {recipient_private_key.key_id.hex()}"
            )

        try:
            data = ciphertext.encrypted_data
            if len(data) < self._MIN_CIPHERTEXT_SIZE:
                raise PREDecryptionError("Ciphertext too short")

            # Unpack: ephemeral_pk || nonce || ciphertext_with_tag
            eph_public = data[: self._EPHEMERAL_PK_SIZE]
            nonce = data[self._EPHEMERAL_PK_SIZE : self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE]
            aes_ciphertext = data[self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE :]

            # DH with ephemeral public key
            shared_secret = x25519_dh(recipient_private_key.key_bytes, eph_public)

            # Derive data encryption key (same derivation as encrypt)
            dek = hkdf_derive(shared_secret, _LABEL_DEK + recipient_private_key.key_id, length=32)

            # Decrypt
            return aes_gcm_decrypt(dek, nonce, aes_ciphertext)

        except PREDecryptionError:
            raise
        except Exception as e:
            raise PREDecryptionError(f"Decryption failed: {e}") from e

    def re_encrypt(
        self,
        ciphertext: PRECiphertext,
        rekey: ReEncryptionKey,
    ) -> PRECiphertext:
        """Re-encrypt ciphertext for a new recipient.

        Trusted-proxy re-encryption:
        1. Recover the DEK from backend cache
        2. Decrypt the original ciphertext using the stored DEK
        3. Re-encrypt via fresh ECIES for the delegatee (new ephemeral DH)
        4. Cache the new DEK for potential chained re-encryption

        The proxy temporarily holds the plaintext during re-encryption.
        This is the explicit trade-off of trusted-proxy PRE.
        """
        if ciphertext.recipient_id != rekey.delegator_id:
            raise PREReEncryptionError(
                f"Rekey delegator {rekey.delegator_id.hex()} "
                f"doesn't match ciphertext recipient {ciphertext.recipient_id.hex()}"
            )

        if rekey.is_expired:
            raise PREReEncryptionError("Re-encryption key has expired")

        # Recover DEK from trusted proxy cache
        dek_entry = self._deks.get(ciphertext.ciphertext_id)
        if dek_entry is None:
            raise PREReEncryptionError(
                "Cannot re-encrypt: DEK not found. "
                "Only ciphertexts created by this backend instance can be re-encrypted."
            )

        dek, stored_recipient_id = dek_entry
        if stored_recipient_id != rekey.delegator_id:
            raise PREReEncryptionError("DEK recipient mismatch with rekey delegator")

        # Look up delegatee's public key
        delegatee_pk_bytes = self._public_keys.get(rekey.delegatee_id)
        if delegatee_pk_bytes is None:
            raise PREReEncryptionError(
                f"Delegatee public key not found for {rekey.delegatee_id.hex()}. "
                "Register via generate_keypair() or generate_rekey() first."
            )

        try:
            # Decrypt original ciphertext using stored DEK
            data = ciphertext.encrypted_data
            nonce = data[self._EPHEMERAL_PK_SIZE : self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE]
            aes_ciphertext = data[self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE :]
            plaintext = aes_gcm_decrypt(dek, nonce, aes_ciphertext)

            # Fresh ECIES encryption for the delegatee
            new_eph_private, new_eph_public = x25519_generate()
            new_shared_secret = x25519_dh(new_eph_private, delegatee_pk_bytes)
            new_dek = hkdf_derive(new_shared_secret, _LABEL_DEK + rekey.delegatee_id, length=32)

            new_ciphertext_data, new_nonce = aes_gcm_encrypt(new_dek, plaintext)
            new_encrypted_data = new_eph_public + new_nonce + new_ciphertext_data

        except PREReEncryptionError:
            raise
        except Exception as e:
            raise PREReEncryptionError(f"Re-encryption failed: {e}") from e

        new_ciphertext_id = crypto_secrets.token_bytes(16)

        # Cache new DEK for potential chained re-encryption
        self._deks[new_ciphertext_id] = (new_dek, rekey.delegatee_id)

        return PRECiphertext(
            ciphertext_id=new_ciphertext_id,
            encrypted_data=new_encrypted_data,
            recipient_id=rekey.delegatee_id,
            is_reencrypted=True,
            original_recipient_id=ciphertext.recipient_id,
            created_at=datetime.now(),
            metadata={
                **ciphertext.metadata,
                "reencrypted_from": ciphertext.ciphertext_id.hex(),
                "rekey_id": rekey.rekey_id.hex(),
            },
        )

    def verify_ciphertext(self, ciphertext: PRECiphertext) -> bool:
        """Verify ciphertext structure and optionally auth tag.

        Checks that the ciphertext has the correct format (ephemeral_pk + nonce
        + GCM data). If the DEK is cached, also verifies the AES-GCM auth tag.
        """
        data = ciphertext.encrypted_data
        if len(data) < self._MIN_CIPHERTEXT_SIZE:
            return False

        # If we have the DEK, verify the auth tag
        dek_entry = self._deks.get(ciphertext.ciphertext_id)
        if dek_entry is not None:
            dek, _ = dek_entry
            try:
                nonce = data[self._EPHEMERAL_PK_SIZE : self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE]
                aes_ciphertext = data[self._EPHEMERAL_PK_SIZE + self._NONCE_SIZE :]
                aes_gcm_decrypt(dek, nonce, aes_ciphertext)
                return True
            except Exception:
                return False

        return True  # Structure valid but can't verify auth tag without DEK
