# ⚠️ DEPRECATED

This library was part of the Ourochronos brick system. It has been removed as a dependency and is no longer maintained.
This repo is archived for reference only.

---

# our-crypto

Cryptographic abstractions for proxy re-encryption, MLS group messaging, and zero-knowledge proofs in the ourochronos ecosystem.

## Overview

our-crypto provides abstract interfaces with both mock and real implementations for three cryptographic primitives used across the ourochronos stack:

- **Proxy Re-Encryption (PRE)** — Allows a proxy to transform ciphertext from one key to another without decrypting it. Used for secure federation aggregation where a relay can re-encrypt shared beliefs without seeing the plaintext.
- **MLS (Messaging Layer Security)** — Group key agreement per RFC 9420 with forward secrecy, post-compromise security, and epoch-based key ratcheting. Powers encrypted group communication.
- **Zero-Knowledge Proofs (ZKP)** — Proves compliance properties (consent, policy adherence, domain membership) without revealing underlying data.

### Backend Status

| Primitive | Mock | Real | Crypto Library | Notes |
|-----------|------|------|---------------|-------|
| PRE | `MockPREBackend` | `X25519PREBackend` | `cryptography` (X25519 + HKDF + AES-256-GCM) | Trusted-proxy ECIES. Blind PRE upgrade path via pairing-based crypto. |
| MLS | `MockMLSBackend` | `HKDFMLSBackend` | `cryptography` (X25519 + HKDF + Ed25519) | Flat member list. Full TreeKEM upgrade path for O(log n) updates. |
| ZKP | `MockZKPBackend` | `SigmaZKPBackend` | `cryptography` (SHA-256) + optional `py-ecc` (BLS12-381) | Sigma protocols with Fiat-Shamir. Pedersen commitments when py-ecc installed. |

## Install

```bash
pip install our-crypto
```

Runtime dependency: `cryptography>=42.0` (PyCA, audited).

Optional for BLS12-381 Pedersen commitments in ZKP:
```bash
pip install our-crypto[zkp]
```

## Usage

### Factory Functions

```python
from our_crypto import create_pre_backend, create_mls_backend, create_zkp_backend

# Mock backends (for testing)
pre = create_pre_backend("mock")
mls = create_mls_backend("mock")
zkp = create_zkp_backend("mock")

# Real backends (for production)
pre = create_pre_backend("x25519")
mls = create_mls_backend("hkdf")
zkp = create_zkp_backend("sigma")
```

### Proxy Re-Encryption

```python
from our_crypto import create_pre_backend

backend = create_pre_backend("x25519")

# Generate keypairs
alice = backend.generate_keypair(b"alice")
bob = backend.generate_keypair(b"bob")

# Encrypt for Alice
ciphertext = backend.encrypt(b"shared belief data", alice.public_key)

# Generate re-encryption key (Alice -> Bob)
rekey = backend.generate_rekey(alice.private_key, bob.public_key)

# Re-encrypt without decrypting (proxy operation)
re_encrypted = backend.re_encrypt(ciphertext, rekey)

# Bob decrypts
plaintext = backend.decrypt(re_encrypted, bob.private_key)
```

### MLS Group Messaging

```python
from our_crypto import create_mls_backend

backend = create_mls_backend("hkdf")

# Create a group
group = backend.create_group(b"group-123", creator_id=b"alice")

# Add members (epoch advances, key schedule ratchets)
group = backend.add_member(group.group_id, b"bob", b"bob-key-package")

# Get current key schedule (HKDF-derived)
key_schedule = backend.get_key_schedule(group.group_id)
```

### Zero-Knowledge Proofs

```python
from our_crypto import create_zkp_backend, ComplianceProofType

backend = create_zkp_backend("sigma")
backend.setup(ComplianceProofType.HAS_CONSENT)

# Prove consent without revealing the record
prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
proof = prover.prove(
    private_inputs={"consent_record": b"..."},
    public_inputs={"user_id": "alice", "action": "read"},
)

# Verify independently
verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)
result = verifier.verify(proof, {"user_id": "alice", "action": "read"})
assert result.valid
```

## API

### PRE

| Class | Description |
|-------|-------------|
| `PREBackend` | Abstract interface for proxy re-encryption |
| `MockPREBackend` | In-memory mock implementation (XOR, no real crypto) |
| `X25519PREBackend` | Real ECIES implementation (X25519 + HKDF + AES-256-GCM) |
| `PREKeyPair`, `PREPublicKey`, `PREPrivateKey` | Key types |
| `ReEncryptionKey` | Unidirectional re-encryption key with optional expiration |
| `PRECiphertext` | Encrypted data container |

### MLS

| Class | Description |
|-------|-------------|
| `MLSBackend` | Abstract interface for MLS group operations |
| `MockMLSBackend` | In-memory mock implementation (SHA-256 derivation) |
| `HKDFMLSBackend` | Real implementation (X25519 DH + HKDF + Ed25519 signatures) |
| `MLSGroup`, `MLSMember` | Group and member state |
| `MLSKeySchedule` | Epoch-based key schedule |
| `MLSProposal`, `MLSCommit` | Add/Remove/Update proposals |

### ZKP

| Class | Description |
|-------|-------------|
| `ZKPBackend`, `ZKPProver`, `ZKPVerifier` | Abstract interfaces |
| `MockZKPBackend`, `MockZKPProver`, `MockZKPVerifier` | Mock implementations |
| `SigmaZKPBackend`, `SigmaZKPProver`, `SigmaZKPVerifier` | Real Sigma protocol implementations |
| `ComplianceProof` | Proof with metadata and expiration |
| `ComplianceProofType` | `HAS_CONSENT`, `WITHIN_POLICY`, `NOT_REVOKED`, `MEMBER_OF_DOMAIN` |
| `VerificationResult` | Verification outcome with timing |

### Factory Functions

| Function | Backends |
|----------|----------|
| `create_pre_backend(backend)` | `"mock"` \| `"x25519"` |
| `create_mls_backend(backend)` | `"mock"` \| `"hkdf"` |
| `create_zkp_backend(backend)` | `"mock"` \| `"sigma"` |

## Development

```bash
# Install with dev dependencies
make dev

# Run linters
make lint

# Run tests
make test

# Run tests with coverage
make test-cov

# Auto-format
make format
```

## State Ownership

None. This package is stateless — it provides interfaces and implementations only. Real backends maintain in-memory state for their operation (DEK cache for PRE, group state for MLS, parameters for ZKP) but persist nothing.

## Part of Valence

This brick is part of the [Valence](https://github.com/ourochronos/valence) knowledge substrate. See [our-infra](https://github.com/ourochronos/our-infra) for ourochronos conventions.

## License

MIT
