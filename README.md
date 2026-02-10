# our-crypto

Cryptographic abstractions for proxy re-encryption, MLS group messaging, and zero-knowledge proofs in the ourochronos ecosystem.

## Overview

our-crypto provides abstract interfaces and mock implementations for three cryptographic primitives used across the ourochronos stack:

- **Proxy Re-Encryption (PRE)** — Allows a proxy to transform ciphertext from one key to another without decrypting it. Used for secure federation aggregation where a relay can re-encrypt shared beliefs without seeing the plaintext.
- **MLS (Messaging Layer Security)** — Group key agreement per RFC 9420 with forward secrecy, post-compromise security, and epoch-based key ratcheting. Powers encrypted group communication.
- **Zero-Knowledge Proofs (ZKP)** — Proves compliance properties (consent, policy adherence, domain membership) without revealing underlying data.

All implementations are currently mock/test-focused. Production backends (e.g., pyUmbral for PRE, arkworks for ZKP) can be swapped in by implementing the abstract interfaces.

## Install

```bash
pip install our-crypto
```

No runtime dependencies — this package provides abstractions only.

## Usage

### Proxy Re-Encryption

```python
from our_crypto import MockPREBackend

backend = MockPREBackend()

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
from our_crypto import MockMLSBackend

backend = MockMLSBackend()

# Create a group
group = backend.create_group(b"group-123", creator_id=b"alice")

# Add members
group = backend.add_member(group.group_id, b"bob", b"bob-key-package")

# Get current key schedule
key_schedule = backend.get_key_schedule(group.group_id)
```

### Zero-Knowledge Proofs

```python
from our_crypto import MockZKPBackend, ComplianceProofType

backend = MockZKPBackend()
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
| `MockPREBackend` | In-memory mock implementation |
| `PREKeyPair`, `PREPublicKey`, `PREPrivateKey` | Key types |
| `ReEncryptionKey` | Unidirectional re-encryption key with optional expiration |
| `PRECiphertext` | Encrypted data container |

### MLS

| Class | Description |
|-------|-------------|
| `MLSBackend` | Abstract interface for MLS group operations |
| `MockMLSBackend` | In-memory mock implementation |
| `MLSGroup`, `MLSMember` | Group and member state |
| `MLSKeySchedule` | Epoch-based key schedule |
| `MLSProposal`, `MLSCommit` | Add/Remove/Update proposals |

### ZKP

| Class | Description |
|-------|-------------|
| `ZKPBackend`, `ZKPProver`, `ZKPVerifier` | Abstract interfaces |
| `MockZKPBackend`, `MockZKPProver`, `MockZKPVerifier` | Mock implementations |
| `ComplianceProof` | Proof with metadata and expiration |
| `ComplianceProofType` | `HAS_CONSENT`, `WITHIN_POLICY`, `NOT_REVOKED`, `MEMBER_OF_DOMAIN` |
| `VerificationResult` | Verification outcome with timing |

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

None. This package is stateless — it provides interfaces and in-memory mock implementations only.

## Part of Valence

This brick is part of the [Valence](https://github.com/ourochronos/valence) knowledge substrate. See [our-infra](https://github.com/ourochronos/our-infra) for ourochronos conventions.

## License

MIT
