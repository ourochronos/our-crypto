"""our-crypto -- Cryptographic primitives for the ourochronos ecosystem.

This module provides cryptographic abstractions including:
- MLS (Messaging Layer Security) for group encryption
- ZKP (Zero-Knowledge Proofs) for compliance verification
- PRE (Proxy Re-Encryption) for federation aggregation

Each primitive has a mock backend (for testing) and a real backend
(using the `cryptography` library for actual crypto operations).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "0.1.0"

from our_crypto.mls import (
    MLSBackend,
    MLSEpochMismatchError,
    MLSError,
    MLSGroup,
    MLSGroupNotFoundError,
    MLSKeySchedule,
    MLSMember,
    MLSMemberNotFoundError,
    MockMLSBackend,
)
from our_crypto.pre import (
    # Mock implementation
    MockPREBackend,
    # Abstract interface
    PREBackend,
    PRECiphertext,
    PREDecryptionError,
    PREEncryptionError,
    # Exceptions
    PREError,
    PREInvalidCiphertextError,
    PREKeyError,
    PREKeyPair,
    PREPrivateKey,
    # Data classes
    PREPublicKey,
    PREReEncryptionError,
    ReEncryptionKey,
    # Utilities
    create_mock_backend,
)
from our_crypto.zkp import (
    ComplianceProof,
    # Types
    ComplianceProofType,
    MockZKPBackend,
    # Mock implementations
    MockZKPProver,
    MockZKPVerifier,
    PublicParameters,
    VerificationResult,
    ZKPBackend,
    ZKPCircuitNotFoundError,
    # Exceptions
    ZKPError,
    ZKPInputError,
    ZKPInvalidProofError,
    # Abstract interfaces
    ZKPProver,
    ZKPProvingError,
    ZKPVerificationError,
    ZKPVerifier,
    # Utilities
    hash_public_inputs,
    verify_proof,
)

if TYPE_CHECKING:
    from our_crypto.mls_real import HKDFMLSBackend as HKDFMLSBackend
    from our_crypto.pre_real import X25519PREBackend as X25519PREBackend
    from our_crypto.zkp_real import SigmaZKPBackend as SigmaZKPBackend
    from our_crypto.zkp_real import SigmaZKPProver as SigmaZKPProver
    from our_crypto.zkp_real import SigmaZKPVerifier as SigmaZKPVerifier


# =============================================================================
# Factory Functions (lazy imports for real backends)
# =============================================================================


def create_pre_backend(backend: str = "mock") -> PREBackend:
    """Create a PRE backend.

    Args:
        backend: "mock" for testing, "x25519" for real crypto

    Returns:
        PREBackend instance
    """
    if backend == "mock":
        return MockPREBackend()
    elif backend == "x25519":
        from our_crypto.pre_real import X25519PREBackend

        return X25519PREBackend()
    else:
        raise ValueError(f"Unknown PRE backend: {backend!r}. Use 'mock' or 'x25519'.")


def create_mls_backend(backend: str = "mock") -> MLSBackend:
    """Create an MLS backend.

    Args:
        backend: "mock" for testing, "hkdf" for real crypto

    Returns:
        MLSBackend instance
    """
    if backend == "mock":
        return MockMLSBackend()
    elif backend == "hkdf":
        from our_crypto.mls_real import HKDFMLSBackend

        return HKDFMLSBackend()
    else:
        raise ValueError(f"Unknown MLS backend: {backend!r}. Use 'mock' or 'hkdf'.")


def create_zkp_backend(backend: str = "mock") -> ZKPBackend:
    """Create a ZKP backend.

    Args:
        backend: "mock" for testing, "sigma" for real crypto

    Returns:
        ZKPBackend instance
    """
    if backend == "mock":
        return MockZKPBackend()
    elif backend == "sigma":
        from our_crypto.zkp_real import SigmaZKPBackend

        return SigmaZKPBackend()
    else:
        raise ValueError(f"Unknown ZKP backend: {backend!r}. Use 'mock' or 'sigma'.")


__all__ = [
    # MLS
    "MLSGroup",
    "MLSMember",
    "MLSKeySchedule",
    "MLSBackend",
    "MockMLSBackend",
    "MLSError",
    "MLSGroupNotFoundError",
    "MLSMemberNotFoundError",
    "MLSEpochMismatchError",
    # ZKP Exceptions
    "ZKPError",
    "ZKPInvalidProofError",
    "ZKPCircuitNotFoundError",
    "ZKPProvingError",
    "ZKPVerificationError",
    "ZKPInputError",
    # ZKP Types
    "ComplianceProofType",
    "PublicParameters",
    "ComplianceProof",
    "VerificationResult",
    # ZKP Interfaces
    "ZKPProver",
    "ZKPVerifier",
    "ZKPBackend",
    # ZKP Mock Implementations
    "MockZKPProver",
    "MockZKPVerifier",
    "MockZKPBackend",
    # ZKP Utilities
    "hash_public_inputs",
    "verify_proof",
    # PRE Exceptions
    "PREError",
    "PREKeyError",
    "PREEncryptionError",
    "PREDecryptionError",
    "PREReEncryptionError",
    "PREInvalidCiphertextError",
    # PRE Data Classes
    "PREPublicKey",
    "PREPrivateKey",
    "PREKeyPair",
    "ReEncryptionKey",
    "PRECiphertext",
    # PRE Interfaces
    "PREBackend",
    # PRE Mock Implementation
    "MockPREBackend",
    # PRE Utilities
    "create_mock_backend",
    # Factory Functions
    "create_pre_backend",
    "create_mls_backend",
    "create_zkp_backend",
]
