"""Public interface for our-crypto.

This module re-exports the primary public API: abstract interfaces,
core types, mock implementations, real implementations, exceptions,
factory functions, and utility functions.

Usage:
    from our_crypto.interface import MLSBackend, PREBackend, ZKPBackend
    from our_crypto.interface import MockMLSBackend, MockPREBackend, MockZKPBackend
    from our_crypto.interface import create_pre_backend, create_mls_backend, create_zkp_backend
"""

from our_crypto import create_mls_backend, create_pre_backend, create_zkp_backend
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
from our_crypto.mls_real import HKDFMLSBackend
from our_crypto.pre import (
    MockPREBackend,
    PREBackend,
    PRECiphertext,
    PREDecryptionError,
    PREEncryptionError,
    PREError,
    PREInvalidCiphertextError,
    PREKeyError,
    PREKeyPair,
    PREPrivateKey,
    PREPublicKey,
    PREReEncryptionError,
    ReEncryptionKey,
    create_mock_backend,
)
from our_crypto.pre_real import X25519PREBackend
from our_crypto.zkp import (
    ComplianceProof,
    ComplianceProofType,
    MockZKPBackend,
    MockZKPProver,
    MockZKPVerifier,
    PublicParameters,
    VerificationResult,
    ZKPBackend,
    ZKPCircuitNotFoundError,
    ZKPError,
    ZKPInputError,
    ZKPInvalidProofError,
    ZKPProver,
    ZKPProvingError,
    ZKPVerificationError,
    ZKPVerifier,
    hash_public_inputs,
    verify_proof,
)
from our_crypto.zkp_real import SigmaZKPBackend, SigmaZKPProver, SigmaZKPVerifier

__all__ = [
    # MLS Interfaces
    "MLSBackend",
    "MockMLSBackend",
    "HKDFMLSBackend",
    # MLS Types
    "MLSGroup",
    "MLSMember",
    "MLSKeySchedule",
    # MLS Exceptions
    "MLSError",
    "MLSGroupNotFoundError",
    "MLSMemberNotFoundError",
    "MLSEpochMismatchError",
    # ZKP Interfaces
    "ZKPProver",
    "ZKPVerifier",
    "ZKPBackend",
    "MockZKPProver",
    "MockZKPVerifier",
    "MockZKPBackend",
    "SigmaZKPProver",
    "SigmaZKPVerifier",
    "SigmaZKPBackend",
    # ZKP Types
    "ComplianceProofType",
    "PublicParameters",
    "ComplianceProof",
    "VerificationResult",
    # ZKP Exceptions
    "ZKPError",
    "ZKPInvalidProofError",
    "ZKPCircuitNotFoundError",
    "ZKPProvingError",
    "ZKPVerificationError",
    "ZKPInputError",
    # ZKP Utilities
    "hash_public_inputs",
    "verify_proof",
    # PRE Interfaces
    "PREBackend",
    "MockPREBackend",
    "X25519PREBackend",
    # PRE Types
    "PREPublicKey",
    "PREPrivateKey",
    "PREKeyPair",
    "ReEncryptionKey",
    "PRECiphertext",
    # PRE Exceptions
    "PREError",
    "PREKeyError",
    "PREEncryptionError",
    "PREDecryptionError",
    "PREReEncryptionError",
    "PREInvalidCiphertextError",
    # PRE Utilities
    "create_mock_backend",
    # Factory Functions
    "create_pre_backend",
    "create_mls_backend",
    "create_zkp_backend",
]
