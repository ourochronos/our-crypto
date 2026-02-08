"""Public interface for oro-crypto.

This module re-exports the primary public API: abstract interfaces,
core types, mock implementations, exceptions, and utility functions.

Usage:
    from oro_crypto.interface import MLSBackend, PREBackend, ZKPBackend
    from oro_crypto.interface import MockMLSBackend, MockPREBackend, MockZKPBackend
"""

from oro_crypto.mls import (
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
from oro_crypto.pre import (
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
from oro_crypto.zkp import (
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

__all__ = [
    # MLS Interfaces
    "MLSBackend",
    "MockMLSBackend",
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
]
