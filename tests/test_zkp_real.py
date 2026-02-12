"""Tests for Sigma Protocol ZKP backend.

These tests verify the real Sigma protocol ZKP backend provides actual
cryptographic soundness while matching the interface contract.
"""

from datetime import datetime, timedelta

import pytest

from our_crypto.zkp import (
    ComplianceProofType,
    ZKPBackend,
    ZKPCircuitNotFoundError,
    ZKPInputError,
    ZKPProver,
    ZKPVerifier,
    hash_public_inputs,
)
from our_crypto.zkp_real import (
    _PROOF_DATA_SIZE,
    SigmaZKPBackend,
    SigmaZKPProver,
    SigmaZKPVerifier,
)


class TestSigmaZKPBackendSetup:
    """Tests for backend setup."""

    @pytest.fixture
    def backend(self) -> SigmaZKPBackend:
        return SigmaZKPBackend()

    def test_implements_interface(self, backend: SigmaZKPBackend) -> None:
        """SigmaZKPBackend implements ZKPBackend."""
        assert isinstance(backend, ZKPBackend)

    def test_setup_creates_parameters(self, backend: SigmaZKPBackend) -> None:
        """Setup generates public parameters."""
        params = backend.setup(ComplianceProofType.HAS_CONSENT)

        assert params.proof_type == ComplianceProofType.HAS_CONSENT
        assert len(params.circuit_hash) == 32
        assert len(params.verification_key) == 32
        assert len(params.proving_key_hash) == 32

    def test_setup_deterministic(self, backend: SigmaZKPBackend) -> None:
        """Setup is deterministic (Sigma protocols are transparent)."""
        backend2 = SigmaZKPBackend()

        params1 = backend.setup(ComplianceProofType.HAS_CONSENT)
        params2 = backend2.setup(ComplianceProofType.HAS_CONSENT)

        assert params1.circuit_hash == params2.circuit_hash
        assert params1.verification_key == params2.verification_key

    def test_setup_all(self, backend: SigmaZKPBackend) -> None:
        """Setup all proof types."""
        all_params = backend.setup_all()
        assert len(all_params) == len(ComplianceProofType)

        for proof_type in ComplianceProofType:
            assert proof_type in all_params

    def test_different_types_different_params(self, backend: SigmaZKPBackend) -> None:
        """Different proof types get different parameters."""
        p1 = backend.setup(ComplianceProofType.HAS_CONSENT)
        p2 = backend.setup(ComplianceProofType.NOT_REVOKED)

        assert p1.circuit_hash != p2.circuit_hash

    def test_create_prover_requires_setup(self, backend: SigmaZKPBackend) -> None:
        """Creating prover without setup raises error."""
        with pytest.raises(ZKPCircuitNotFoundError):
            backend.create_prover(ComplianceProofType.HAS_CONSENT)

    def test_create_verifier_requires_setup(self, backend: SigmaZKPBackend) -> None:
        """Creating verifier without setup raises error."""
        with pytest.raises(ZKPCircuitNotFoundError):
            backend.create_verifier(ComplianceProofType.HAS_CONSENT)

    def test_get_public_parameters(self, backend: SigmaZKPBackend) -> None:
        """Get parameters returns None before setup, params after."""
        assert backend.get_public_parameters(ComplianceProofType.HAS_CONSENT) is None
        backend.setup(ComplianceProofType.HAS_CONSENT)
        assert backend.get_public_parameters(ComplianceProofType.HAS_CONSENT) is not None


class TestSigmaZKPProver:
    """Tests for Sigma protocol prover."""

    @pytest.fixture
    def backend(self) -> SigmaZKPBackend:
        b = SigmaZKPBackend()
        b.setup_all()
        return b

    def test_prover_implements_interface(self, backend: SigmaZKPBackend) -> None:
        """SigmaZKPProver implements ZKPProver."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        assert isinstance(prover, ZKPProver)
        assert isinstance(prover, SigmaZKPProver)

    def test_prove_has_consent(self, backend: SigmaZKPBackend) -> None:
        """Generate proof of consent."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        proof = prover.prove(
            private_inputs={"consent_record": b"consent-hash-123"},
            public_inputs={"user_id": "alice", "action": "read"},
        )

        assert proof.proof_type == ComplianceProofType.HAS_CONSENT
        assert len(proof.proof_data) == _PROOF_DATA_SIZE
        assert len(proof.public_inputs_hash) == 32
        assert proof.metadata["backend"] == "sigma"

    def test_prove_within_policy(self, backend: SigmaZKPBackend) -> None:
        """Generate proof of policy compliance."""
        prover = backend.create_prover(ComplianceProofType.WITHIN_POLICY)
        proof = prover.prove(
            private_inputs={"operation_details": "read belief", "policy_evaluation": "approved"},
            public_inputs={"policy_hash": "abc123", "operation_type": "read"},
        )
        assert proof.proof_type == ComplianceProofType.WITHIN_POLICY
        assert len(proof.proof_data) == _PROOF_DATA_SIZE

    def test_prove_not_revoked(self, backend: SigmaZKPBackend) -> None:
        """Generate proof of non-revocation."""
        prover = backend.create_prover(ComplianceProofType.NOT_REVOKED)
        proof = prover.prove(
            private_inputs={"credential": b"cred-data", "revocation_proof": b"proof"},
            public_inputs={"credential_commitment": "commit", "revocation_accumulator": "accum"},
        )
        assert proof.proof_type == ComplianceProofType.NOT_REVOKED

    def test_prove_member_of_domain(self, backend: SigmaZKPBackend) -> None:
        """Generate proof of domain membership."""
        prover = backend.create_prover(ComplianceProofType.MEMBER_OF_DOMAIN)
        proof = prover.prove(
            private_inputs={"member_credential": b"member", "merkle_proof": b"path"},
            public_inputs={"domain_id": "domain-1", "membership_root": "root-hash"},
        )
        assert proof.proof_type == ComplianceProofType.MEMBER_OF_DOMAIN

    def test_prove_nondeterministic(self, backend: SigmaZKPBackend) -> None:
        """Same inputs produce different proofs (fresh randomness each time)."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        private = {"consent_record": b"record"}
        public = {"user_id": "alice", "action": "read"}

        proof1 = prover.prove(private, public)
        proof2 = prover.prove(private, public)

        # Different proof data (different randomness)
        assert proof1.proof_data != proof2.proof_data
        # Same public inputs hash
        assert proof1.public_inputs_hash == proof2.public_inputs_hash

    def test_missing_private_inputs_fails(self, backend: SigmaZKPBackend) -> None:
        """Missing private inputs raises ZKPInputError."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        with pytest.raises(ZKPInputError, match="private inputs"):
            prover.prove(
                private_inputs={},
                public_inputs={"user_id": "alice", "action": "read"},
            )

    def test_missing_public_inputs_fails(self, backend: SigmaZKPBackend) -> None:
        """Missing public inputs raises ZKPInputError."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        with pytest.raises(ZKPInputError, match="public inputs"):
            prover.prove(
                private_inputs={"consent_record": b"record"},
                public_inputs={},
            )

    def test_extra_inputs_allowed(self, backend: SigmaZKPBackend) -> None:
        """Extra inputs are allowed (not rejected)."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        proof = prover.prove(
            private_inputs={"consent_record": b"record", "extra": "data"},
            public_inputs={"user_id": "alice", "action": "read", "bonus": "field"},
        )
        assert len(proof.proof_data) == _PROOF_DATA_SIZE


class TestSigmaZKPVerifier:
    """Tests for Sigma protocol verifier."""

    @pytest.fixture
    def backend(self) -> SigmaZKPBackend:
        b = SigmaZKPBackend()
        b.setup_all()
        return b

    def test_verifier_implements_interface(self, backend: SigmaZKPBackend) -> None:
        """SigmaZKPVerifier implements ZKPVerifier."""
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)
        assert isinstance(verifier, ZKPVerifier)
        assert isinstance(verifier, SigmaZKPVerifier)

    def test_verify_valid_proof(self, backend: SigmaZKPBackend) -> None:
        """Valid proof passes verification."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "read"}
        proof = prover.prove(
            private_inputs={"consent_record": b"record"},
            public_inputs=public,
        )

        result = verifier.verify(proof, public)
        assert result.valid
        assert result.verification_time_ms >= 0

    def test_verify_wrong_public_inputs_fails(self, backend: SigmaZKPBackend) -> None:
        """Verification fails with different public inputs."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        proof = prover.prove(
            private_inputs={"consent_record": b"record"},
            public_inputs={"user_id": "alice", "action": "read"},
        )

        result = verifier.verify(proof, {"user_id": "bob", "action": "read"})
        assert not result.valid
        assert "hash mismatch" in (result.error_message or "").lower()

    def test_verify_wrong_proof_type_fails(self, backend: SigmaZKPBackend) -> None:
        """Verification fails for wrong proof type."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.NOT_REVOKED)

        proof = prover.prove(
            private_inputs={"consent_record": b"record"},
            public_inputs={"user_id": "alice", "action": "read"},
        )

        result = verifier.verify(proof, {"user_id": "alice", "action": "read"})
        assert not result.valid

    def test_verify_expired_proof_fails(self, backend: SigmaZKPBackend) -> None:
        """Expired proof fails verification."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "read"}
        proof = prover.prove({"consent_record": b"record"}, public)

        # Force expiration
        proof.expires_at = datetime.now() - timedelta(hours=1)

        result = verifier.verify(proof, public)
        assert not result.valid
        assert "expired" in (result.error_message or "").lower()

    def test_verify_tampered_proof_fails(self, backend: SigmaZKPBackend) -> None:
        """Tampered proof data fails verification (Fiat-Shamir check)."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "read"}
        proof = prover.prove({"consent_record": b"record"}, public)

        # Tamper with the commitment (first 32 bytes)
        tampered_data = bytearray(proof.proof_data)
        tampered_data[0] ^= 0xFF
        proof.proof_data = bytes(tampered_data)

        result = verifier.verify(proof, public)
        assert not result.valid
        assert "challenge" in (result.error_message or "").lower() or "binding" in (result.error_message or "").lower()

    def test_verify_wrong_length_fails(self, backend: SigmaZKPBackend) -> None:
        """Wrong proof data length fails verification."""
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        from our_crypto.zkp import ComplianceProof

        bad_proof = ComplianceProof(
            proof_type=ComplianceProofType.HAS_CONSENT,
            proof_data=b"\x00" * 64,  # Wrong size
            public_inputs_hash=hash_public_inputs({"user_id": "alice", "action": "read"}),
        )

        result = verifier.verify(bad_proof, {"user_id": "alice", "action": "read"})
        assert not result.valid
        assert "length" in (result.error_message or "").lower()

    def test_tampered_response_fails(self, backend: SigmaZKPBackend) -> None:
        """Tampered response bytes fail binding verification."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "read"}
        proof = prover.prove({"consent_record": b"record"}, public)

        # Tamper with response (bytes 64-96)
        tampered_data = bytearray(proof.proof_data)
        tampered_data[65] ^= 0xFF
        proof.proof_data = bytes(tampered_data)

        result = verifier.verify(proof, public)
        assert not result.valid


class TestSigmaZKPEndToEnd:
    """End-to-end workflow tests."""

    @pytest.fixture
    def backend(self) -> SigmaZKPBackend:
        b = SigmaZKPBackend()
        b.setup_all()
        return b

    def test_consent_workflow(self, backend: SigmaZKPBackend) -> None:
        """Full consent proof workflow: prove -> verify."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "share_belief"}
        proof = prover.prove({"consent_record": b"alice-consented-2024"}, public)

        result = verifier.verify(proof, public)
        assert result.valid

    def test_domain_membership_workflow(self, backend: SigmaZKPBackend) -> None:
        """Full domain membership proof workflow."""
        prover = backend.create_prover(ComplianceProofType.MEMBER_OF_DOMAIN)
        verifier = backend.create_verifier(ComplianceProofType.MEMBER_OF_DOMAIN)

        public = {"domain_id": "research-group", "membership_root": "merkle-root-abc"}
        proof = prover.prove(
            {"member_credential": b"member-cert", "merkle_proof": b"leaf+path"},
            public,
        )

        result = verifier.verify(proof, public)
        assert result.valid

    def test_multiple_proofs_independently_verifiable(self, backend: SigmaZKPBackend) -> None:
        """Multiple proofs of different types verify independently."""
        proofs = {}
        publics = {}

        for pt, private, public in [
            (ComplianceProofType.HAS_CONSENT, {"consent_record": b"c"}, {"user_id": "a", "action": "r"}),
            (
                ComplianceProofType.WITHIN_POLICY,
                {"operation_details": "op", "policy_evaluation": "pass"},
                {"policy_hash": "ph", "operation_type": "read"},
            ),
            (
                ComplianceProofType.NOT_REVOKED,
                {"credential": b"cred", "revocation_proof": b"rp"},
                {"credential_commitment": "cc", "revocation_accumulator": "ra"},
            ),
            (
                ComplianceProofType.MEMBER_OF_DOMAIN,
                {"member_credential": b"mc", "merkle_proof": b"mp"},
                {"domain_id": "d", "membership_root": "mr"},
            ),
        ]:
            prover = backend.create_prover(pt)
            proofs[pt] = prover.prove(private, public)
            publics[pt] = public

        # Verify each
        for pt in ComplianceProofType:
            verifier = backend.create_verifier(pt)
            result = verifier.verify(proofs[pt], publics[pt])
            assert result.valid, f"Failed for {pt.name}"

    def test_cross_backend_verification(self) -> None:
        """Proof from one backend instance verifiable by another."""
        backend1 = SigmaZKPBackend()
        backend1.setup(ComplianceProofType.HAS_CONSENT)

        backend2 = SigmaZKPBackend()
        backend2.setup(ComplianceProofType.HAS_CONSENT)

        public = {"user_id": "alice", "action": "read"}
        prover = backend1.create_prover(ComplianceProofType.HAS_CONSENT)
        proof = prover.prove({"consent_record": b"record"}, public)

        verifier = backend2.create_verifier(ComplianceProofType.HAS_CONSENT)
        result = verifier.verify(proof, public)
        assert result.valid

    def test_proof_serialization_roundtrip(self, backend: SigmaZKPBackend) -> None:
        """Proof survives serialization/deserialization."""
        prover = backend.create_prover(ComplianceProofType.HAS_CONSENT)
        public = {"user_id": "alice", "action": "read"}
        proof = prover.prove({"consent_record": b"record"}, public)

        # Serialize and deserialize
        data = proof.to_dict()
        from our_crypto.zkp import ComplianceProof

        restored = ComplianceProof.from_dict(data)

        verifier = backend.create_verifier(ComplianceProofType.HAS_CONSENT)
        result = verifier.verify(restored, public)
        assert result.valid
