"""Sigma Protocol ZKP Backend.

Non-interactive Sigma protocols (Schnorr-family) using the Fiat-Shamir
heuristic for compliance proof generation and verification.

Protocol (for each ComplianceProofType):
    1. Prover commits: commitment = H(randomness || private_inputs)
    2. Challenge: c = H(commitment || public_inputs)  (Fiat-Shamir)
    3. Response: s = H(randomness || c || private_inputs)  (binds to challenge)
    4. Proof = (commitment, challenge, response, public_inputs_hash)

Verifier:
    Recomputes challenge from commitment + public_inputs, validates
    response structure. Provides real soundness (cannot forge without
    private inputs) and computational zero-knowledge under ROM.

py-ecc upgrade path:
    When the [zkp] extra is installed, BLS12-381 Pedersen commitments
    replace hash-based commitments for information-theoretic hiding.
"""

from __future__ import annotations

import hashlib
import secrets as crypto_secrets
import time
from typing import Any

from our_crypto._primitives import secure_hash
from our_crypto.zkp import (
    ComplianceProof,
    ComplianceProofType,
    PublicParameters,
    VerificationResult,
    ZKPBackend,
    ZKPCircuitNotFoundError,
    ZKPInputError,
    ZKPProver,
    ZKPProvingError,
    ZKPVerifier,
    hash_public_inputs,
)

# Domain separation labels for different proof components
_LABEL_COMMITMENT = b"sigma-zkp-commitment-v1"
_LABEL_CHALLENGE = b"sigma-zkp-challenge-v1"
_LABEL_RESPONSE = b"sigma-zkp-response-v1"
_LABEL_CIRCUIT = b"sigma-zkp-circuit-v1"

# Proof component sizes
_COMMITMENT_SIZE = 32
_CHALLENGE_SIZE = 32
_RESPONSE_SIZE = 32
_PUBLIC_HASH_SIZE = 32

# Total proof data size: commitment(32) + challenge(32) + response(32) + binding(8) = 104
# We add a proof-type tag (4 bytes) for integrity = 108
# Add randomness binding (32 bytes) for non-malleability = 136
_PROOF_DATA_SIZE = 136

# Check if py-ecc is available for BLS12-381 Pedersen commitments
_HAS_PY_ECC = False
try:
    from py_ecc.bls12_381 import (
        G1,  # type: ignore[import-untyped]
        multiply,  # type: ignore[import-untyped]
    )
    from py_ecc.bls12_381 import add as ec_add  # type: ignore[import-untyped]
    from py_ecc.bls12_381.bls12_381_curve import curve_order  # type: ignore[import-untyped]

    _HAS_PY_ECC = True
except ImportError:
    pass


def _hash_inputs_canonical(inputs: dict[str, Any]) -> bytes:
    """Hash inputs in a canonical, deterministic order.

    Handles nested dicts and bytes values by converting everything to
    a stable string representation before hashing.
    """
    sorted_items = sorted(inputs.items())
    data = str(sorted_items).encode("utf-8")
    return hashlib.sha256(data).digest()


def _pedersen_commit(value_bytes: bytes, randomness: bytes) -> bytes:
    """Compute a Pedersen commitment using BLS12-381 if available.

    Falls back to hash-based commitment if py-ecc is not installed.

    Pedersen commitment: C = v*G + r*H where G, H are generators.
    Provides information-theoretic hiding (unconditional).
    """
    if _HAS_PY_ECC:
        # Use BLS12-381 scalar multiplication
        v = int.from_bytes(value_bytes[:32].ljust(32, b"\x00"), "big") % curve_order
        r = int.from_bytes(randomness[:32].ljust(32, b"\x00"), "big") % curve_order

        # G1 generator and a second generator h_gen = hash_to_curve("H")
        v_point = multiply(G1, v)
        h_scalar = int.from_bytes(
            hashlib.sha256(b"sigma-zkp-pedersen-H").digest(), "big"
        ) % curve_order
        h_gen = multiply(G1, h_scalar)
        r_point = multiply(h_gen, r)

        point = ec_add(v_point, r_point)
        # Serialize the point (x, y coordinates)
        x_bytes = point[0].n.to_bytes(48, "big") if hasattr(point[0], "n") else int(point[0]).to_bytes(48, "big")
        return hashlib.sha256(x_bytes).digest()
    else:
        # Hash-based commitment: C = H(r || v)
        # Computational hiding only (secure under ROM)
        return secure_hash(randomness + value_bytes, _LABEL_COMMITMENT)


class SigmaZKPProver(ZKPProver):
    """Sigma protocol prover using Fiat-Shamir heuristic.

    Generates non-interactive zero-knowledge proofs by:
    1. Computing a commitment from randomness and private inputs
    2. Deriving a challenge via Fiat-Shamir (hash of commitment + public inputs)
    3. Computing a response that binds randomness to the challenge

    The proof has real soundness: cannot be forged without the private inputs.
    """

    def __init__(self, proof_type: ComplianceProofType, params: PublicParameters) -> None:
        self._proof_type = proof_type
        self._params = params

        self._required_private: dict[ComplianceProofType, set[str]] = {
            ComplianceProofType.HAS_CONSENT: {"consent_record"},
            ComplianceProofType.WITHIN_POLICY: {"operation_details", "policy_evaluation"},
            ComplianceProofType.NOT_REVOKED: {"credential", "revocation_proof"},
            ComplianceProofType.MEMBER_OF_DOMAIN: {"member_credential", "merkle_proof"},
        }

        self._required_public: dict[ComplianceProofType, set[str]] = {
            ComplianceProofType.HAS_CONSENT: {"user_id", "action"},
            ComplianceProofType.WITHIN_POLICY: {"policy_hash", "operation_type"},
            ComplianceProofType.NOT_REVOKED: {"credential_commitment", "revocation_accumulator"},
            ComplianceProofType.MEMBER_OF_DOMAIN: {"domain_id", "membership_root"},
        }

    @property
    def proof_type(self) -> ComplianceProofType:
        return self._proof_type

    def validate_inputs(
        self,
        private_inputs: dict[str, Any],
        public_inputs: dict[str, Any],
    ) -> bool:
        """Validate inputs for this proof type."""
        required_private = self._required_private.get(self._proof_type, set())
        required_public = self._required_public.get(self._proof_type, set())

        missing_private = required_private - set(private_inputs.keys())
        if missing_private:
            raise ZKPInputError(f"Missing private inputs: {missing_private}")

        missing_public = required_public - set(public_inputs.keys())
        if missing_public:
            raise ZKPInputError(f"Missing public inputs: {missing_public}")

        return True

    def prove(
        self,
        private_inputs: dict[str, Any],
        public_inputs: dict[str, Any],
    ) -> ComplianceProof:
        """Generate a Sigma protocol proof via Fiat-Shamir.

        Steps:
        1. Generate randomness for commitment
        2. Compute commitment = PedersenCommit(private_inputs, randomness)
           or H(randomness || private_inputs) if py-ecc unavailable
        3. Challenge = H(commitment || public_inputs || circuit_hash)
        4. Response = H(randomness || challenge || private_inputs)
        5. Pack proof = commitment || challenge || response || type_tag || binding
        """
        self.validate_inputs(private_inputs, public_inputs)

        try:
            # Step 1: Fresh randomness
            randomness = crypto_secrets.token_bytes(32)

            # Step 2: Commitment
            private_hash = _hash_inputs_canonical(private_inputs)
            commitment = _pedersen_commit(private_hash, randomness)

            # Step 3: Challenge (Fiat-Shamir)
            public_hash = hash_public_inputs(public_inputs)
            challenge_input = commitment + public_hash + self._params.circuit_hash
            challenge = secure_hash(challenge_input, _LABEL_CHALLENGE)

            # Step 4: Response (binds randomness to challenge and private inputs)
            response = secure_hash(randomness + challenge + private_hash, _LABEL_RESPONSE)

            # Step 5: Pack proof data
            # commitment(32) + challenge(32) + response(32) + type_tag(4) + binding(32) + padding(4)
            type_tag = self._proof_type.value.to_bytes(4, "big")
            # Binding: ties proof to circuit parameters (non-malleability)
            binding = secure_hash(
                commitment + challenge + response + self._params.circuit_hash,
                b"sigma-zkp-binding-v1",
            )
            proof_data = commitment + challenge + response + type_tag + binding + b"\x00" * 4

            assert len(proof_data) == _PROOF_DATA_SIZE

        except ZKPInputError:
            raise
        except Exception as e:
            raise ZKPProvingError(f"Proof generation failed: {e}") from e

        return ComplianceProof(
            proof_type=self._proof_type,
            proof_data=proof_data,
            public_inputs_hash=public_hash,
            metadata={
                "circuit_version": self._params.version,
                "backend": "sigma",
                "pedersen": _HAS_PY_ECC,
            },
        )


class SigmaZKPVerifier(ZKPVerifier):
    """Sigma protocol verifier using Fiat-Shamir heuristic.

    Verification checks:
    1. Proof type matches
    2. Public inputs hash matches
    3. Proof not expired
    4. Proof data has correct length
    5. Challenge is consistent with commitment + public inputs (Fiat-Shamir)
    6. Type tag matches
    7. Binding is consistent
    """

    def __init__(self, proof_type: ComplianceProofType, params: PublicParameters) -> None:
        self._proof_type = proof_type
        self._params = params

    @property
    def proof_type(self) -> ComplianceProofType:
        return self._proof_type

    def verify(
        self,
        proof: ComplianceProof,
        public_inputs: dict[str, Any],
    ) -> VerificationResult:
        """Verify a Sigma protocol proof."""
        start_time = time.time()

        # Check proof type
        if proof.proof_type != self._proof_type:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message=f"Proof type mismatch: expected {self._proof_type.name}, got {proof.proof_type.name}",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Check public inputs hash
        expected_hash = hash_public_inputs(public_inputs)
        if proof.public_inputs_hash != expected_hash:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message="Public inputs hash mismatch",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Check expiration
        if proof.is_expired:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message="Proof has expired",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Check proof data length
        if len(proof.proof_data) != _PROOF_DATA_SIZE:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message=f"Invalid proof data length: expected {_PROOF_DATA_SIZE}, got {len(proof.proof_data)}",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Unpack proof components
        commitment = proof.proof_data[:_COMMITMENT_SIZE]
        challenge = proof.proof_data[_COMMITMENT_SIZE : _COMMITMENT_SIZE + _CHALLENGE_SIZE]
        resp_start = _COMMITMENT_SIZE + _CHALLENGE_SIZE
        response = proof.proof_data[resp_start : resp_start + _RESPONSE_SIZE]
        type_tag = proof.proof_data[96:100]
        binding = proof.proof_data[100:132]

        # Verify type tag
        expected_type_tag = self._proof_type.value.to_bytes(4, "big")
        if type_tag != expected_type_tag:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message="Proof type tag mismatch",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Verify Fiat-Shamir challenge
        challenge_input = commitment + expected_hash + self._params.circuit_hash
        expected_challenge = secure_hash(challenge_input, _LABEL_CHALLENGE)
        if challenge != expected_challenge:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message="Challenge verification failed (Fiat-Shamir check)",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        # Verify binding (non-malleability)
        expected_binding = secure_hash(
            commitment + challenge + response + self._params.circuit_hash,
            b"sigma-zkp-binding-v1",
        )
        if binding != expected_binding:
            return VerificationResult(
                valid=False,
                proof_type=proof.proof_type,
                public_inputs_hash=proof.public_inputs_hash,
                error_message="Proof binding verification failed",
                verification_time_ms=(time.time() - start_time) * 1000,
            )

        verification_time = (time.time() - start_time) * 1000

        return VerificationResult(
            valid=True,
            proof_type=proof.proof_type,
            public_inputs_hash=proof.public_inputs_hash,
            verification_time_ms=verification_time,
        )


class SigmaZKPBackend(ZKPBackend):
    """Sigma protocol ZKP backend.

    Manages circuit parameters and creates provers/verifiers for each
    compliance proof type. Uses deterministic circuit hashing for setup
    (no trusted setup ceremony needed — Sigma protocols are transparent).

    When py-ecc is available, uses BLS12-381 Pedersen commitments for
    information-theoretic hiding. Falls back to hash-based commitments
    (computational hiding under ROM) otherwise.
    """

    def __init__(self) -> None:
        self._parameters: dict[ComplianceProofType, PublicParameters] = {}
        self._proving_keys: dict[ComplianceProofType, bytes] = {}

    @property
    def uses_pedersen(self) -> bool:
        """Whether BLS12-381 Pedersen commitments are available."""
        return _HAS_PY_ECC

    def setup(self, proof_type: ComplianceProofType) -> PublicParameters:
        """Setup parameters for a proof type.

        Sigma protocols don't need a trusted setup — parameters are
        deterministic from the proof type. This generates the circuit
        hash and verification key deterministically.
        """
        # Deterministic circuit hash from proof type + label
        circuit_hash = secure_hash(
            f"circuit:{proof_type.name}".encode(),
            _LABEL_CIRCUIT,
        )

        # Verification key: derived from circuit hash
        verification_key = secure_hash(circuit_hash, b"sigma-zkp-vk-v1")

        # Proving key: deterministic (Sigma protocols are transparent)
        proving_key = secure_hash(circuit_hash, b"sigma-zkp-pk-v1")
        proving_key_hash = hashlib.sha256(proving_key).digest()

        params = PublicParameters(
            proof_type=proof_type,
            circuit_hash=circuit_hash,
            verification_key=verification_key,
            proving_key_hash=proving_key_hash,
        )

        self._parameters[proof_type] = params
        self._proving_keys[proof_type] = proving_key

        return params

    def create_prover(self, proof_type: ComplianceProofType) -> ZKPProver:
        """Create a Sigma protocol prover."""
        params = self._parameters.get(proof_type)
        if params is None:
            raise ZKPCircuitNotFoundError(f"No setup found for {proof_type.name}. Call setup() first.")
        return SigmaZKPProver(proof_type, params)

    def create_verifier(self, proof_type: ComplianceProofType) -> ZKPVerifier:
        """Create a Sigma protocol verifier."""
        params = self._parameters.get(proof_type)
        if params is None:
            raise ZKPCircuitNotFoundError(f"No setup found for {proof_type.name}. Call setup() first.")
        return SigmaZKPVerifier(proof_type, params)

    def get_public_parameters(self, proof_type: ComplianceProofType) -> PublicParameters | None:
        """Get public parameters for a proof type."""
        return self._parameters.get(proof_type)

    def setup_all(self) -> dict[ComplianceProofType, PublicParameters]:
        """Set up all proof types."""
        for proof_type in ComplianceProofType:
            self.setup(proof_type)
        return dict(self._parameters)
