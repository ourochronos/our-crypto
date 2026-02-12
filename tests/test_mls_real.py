"""Tests for HKDF MLS backend.

These tests verify the real HKDF-based MLS backend provides proper
cryptographic key derivation, forward secrecy, and epoch management.
"""

import pytest

from our_crypto.mls import (
    MLSBackend,
    MLSEpochMismatchError,
    MLSError,
    MLSGroupNotFoundError,
    MLSKeySchedule,
    MLSMemberNotFoundError,
)
from our_crypto.mls_real import HKDFMLSBackend


class TestHKDFMLSBackendCreation:
    """Tests for group creation."""

    @pytest.fixture
    def backend(self) -> HKDFMLSBackend:
        return HKDFMLSBackend()

    def test_implements_interface(self, backend: HKDFMLSBackend) -> None:
        """HKDFMLSBackend implements MLSBackend."""
        assert isinstance(backend, MLSBackend)

    def test_create_group(self, backend: HKDFMLSBackend) -> None:
        """Create a group with initial member."""
        group = backend.create_group(b"group-1", b"alice")

        assert group.group_id == b"group-1"
        assert group.epoch == 0
        assert group.member_count == 1
        assert group.members[0].member_id == b"alice"
        assert group.members[0].leaf_index == 0

    def test_create_group_key_schedule(self, backend: HKDFMLSBackend) -> None:
        """Group creation produces a real HKDF-derived key schedule."""
        group = backend.create_group(b"group-1", b"alice")
        ks = backend.get_key_schedule(group.group_id)

        assert isinstance(ks, MLSKeySchedule)
        assert ks.epoch == 0
        assert len(ks.epoch_secret) == 32
        assert len(ks.application_secret) == 32
        assert len(ks.confirmation_key) == 32
        assert len(ks.membership_key) == 32
        assert len(ks.resumption_psk) == 32
        assert len(ks.exporter_secret) == 32

    def test_key_schedule_secrets_are_distinct(self, backend: HKDFMLSBackend) -> None:
        """All secrets in the key schedule are different (labeled derivation)."""
        backend.create_group(b"group-1", b"alice")
        ks = backend.get_key_schedule(b"group-1")

        secrets = {
            ks.application_secret,
            ks.confirmation_key,
            ks.membership_key,
            ks.resumption_psk,
            ks.exporter_secret,
        }
        assert len(secrets) == 5  # All distinct

    def test_different_groups_different_keys(self, backend: HKDFMLSBackend) -> None:
        """Different groups get different key schedules."""
        backend.create_group(b"group-1", b"alice")
        backend.create_group(b"group-2", b"bob")

        ks1 = backend.get_key_schedule(b"group-1")
        ks2 = backend.get_key_schedule(b"group-2")

        assert ks1.epoch_secret != ks2.epoch_secret
        assert ks1.application_secret != ks2.application_secret

    def test_create_group_with_credential(self, backend: HKDFMLSBackend) -> None:
        """Group creation with credential."""
        group = backend.create_group(b"g", b"alice", credential=b"cert-data")
        assert group.members[0].credential == b"cert-data"

    def test_member_key_package_is_x25519_public(self, backend: HKDFMLSBackend) -> None:
        """Member key_package contains real X25519 public key (32 bytes)."""
        group = backend.create_group(b"g", b"alice")
        assert len(group.members[0].key_package) == 32


class TestHKDFMLSBackendMembership:
    """Tests for member add/remove/update."""

    @pytest.fixture
    def backend(self) -> HKDFMLSBackend:
        return HKDFMLSBackend()

    def test_add_member(self, backend: HKDFMLSBackend) -> None:
        """Add a member advances epoch."""
        group = backend.create_group(b"g", b"alice")
        assert group.epoch == 0

        group = backend.add_member(b"g", b"bob", b"bob-kp")
        assert group.epoch == 1
        assert group.member_count == 2

    def test_add_member_changes_key_schedule(self, backend: HKDFMLSBackend) -> None:
        """Adding a member derives a new key schedule via HKDF ratchet."""
        backend.create_group(b"g", b"alice")
        ks0 = backend.get_key_schedule(b"g")

        backend.add_member(b"g", b"bob", b"bob-kp")
        ks1 = backend.get_key_schedule(b"g")

        assert ks1.epoch == 1
        assert ks1.epoch_secret != ks0.epoch_secret
        assert ks1.application_secret != ks0.application_secret

    def test_add_duplicate_member_fails(self, backend: HKDFMLSBackend) -> None:
        """Adding an existing member raises MLSError."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        with pytest.raises(MLSError, match="already in group"):
            backend.add_member(b"g", b"bob", b"kp")

    def test_add_to_nonexistent_group_fails(self, backend: HKDFMLSBackend) -> None:
        """Adding to nonexistent group raises MLSGroupNotFoundError."""
        with pytest.raises(MLSGroupNotFoundError):
            backend.add_member(b"missing", b"bob", b"kp")

    def test_remove_member(self, backend: HKDFMLSBackend) -> None:
        """Remove a member advances epoch and removes from list."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        group = backend.remove_member(b"g", b"bob", b"alice")
        assert group.member_count == 1
        assert group.get_member(b"bob") is None
        assert group.epoch == 2  # create=0, add=1, remove=2

    def test_remove_member_forward_secrecy(self, backend: HKDFMLSBackend) -> None:
        """Removal creates a new key schedule (removed member can't derive)."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")
        ks_before = backend.get_key_schedule(b"g")

        backend.remove_member(b"g", b"bob", b"alice")
        ks_after = backend.get_key_schedule(b"g")

        assert ks_after.epoch_secret != ks_before.epoch_secret

    def test_remove_nonexistent_member_fails(self, backend: HKDFMLSBackend) -> None:
        """Removing nonexistent member raises MLSMemberNotFoundError."""
        backend.create_group(b"g", b"alice")

        with pytest.raises(MLSMemberNotFoundError):
            backend.remove_member(b"g", b"ghost", b"alice")

    def test_remove_by_nonmember_fails(self, backend: HKDFMLSBackend) -> None:
        """Removal by non-member raises error."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        with pytest.raises(MLSMemberNotFoundError):
            backend.remove_member(b"g", b"bob", b"outsider")

    def test_update_keys(self, backend: HKDFMLSBackend) -> None:
        """Key update rotates member's key material and advances epoch."""
        backend.create_group(b"g", b"alice")
        old_kp = backend.get_group(b"g").members[0].key_package  # type: ignore[union-attr]

        group = backend.update_keys(b"g", b"alice")
        new_kp = group.members[0].key_package

        assert new_kp != old_kp  # Key was rotated
        assert len(new_kp) == 32  # Still valid X25519 public key
        assert group.epoch == 1

    def test_update_keys_changes_schedule(self, backend: HKDFMLSBackend) -> None:
        """Key update derives a new epoch secret (post-compromise security)."""
        backend.create_group(b"g", b"alice")
        ks0 = backend.get_key_schedule(b"g")

        backend.update_keys(b"g", b"alice")
        ks1 = backend.get_key_schedule(b"g")

        assert ks1.epoch_secret != ks0.epoch_secret

    def test_update_nonexistent_member_fails(self, backend: HKDFMLSBackend) -> None:
        """Updating nonexistent member raises error."""
        backend.create_group(b"g", b"alice")

        with pytest.raises(MLSMemberNotFoundError):
            backend.update_keys(b"g", b"ghost")


class TestHKDFMLSBackendProposalCommit:
    """Tests for the propose/commit workflow."""

    @pytest.fixture
    def backend(self) -> HKDFMLSBackend:
        return HKDFMLSBackend()

    def test_propose_and_commit_add(self, backend: HKDFMLSBackend) -> None:
        """Propose add + commit adds member and advances epoch."""
        backend.create_group(b"g", b"alice")
        proposal = backend.propose_add(b"g", b"alice", b"bob", b"bob-kp")

        assert proposal.proposal_type.name == "ADD"
        assert proposal.epoch == 0

        group, commit = backend.commit(b"g", b"alice")
        assert group.member_count == 2
        assert group.get_member(b"bob") is not None
        assert group.epoch == 1

    def test_propose_and_commit_remove(self, backend: HKDFMLSBackend) -> None:
        """Propose remove + commit removes member."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        backend.propose_remove(b"g", b"alice", b"bob")
        group, commit = backend.commit(b"g", b"alice")

        assert group.member_count == 1
        assert group.get_member(b"bob") is None

    def test_commit_selected_proposals(self, backend: HKDFMLSBackend) -> None:
        """Commit only specific proposals."""
        backend.create_group(b"g", b"alice")
        p1 = backend.propose_add(b"g", b"alice", b"bob", b"kp1")
        _p2 = backend.propose_add(b"g", b"alice", b"carol", b"kp2")

        # Only commit first proposal
        group, _ = backend.commit(b"g", b"alice", proposal_refs=[p1.proposal_ref])

        assert group.member_count == 2  # alice + bob
        assert group.get_member(b"bob") is not None
        assert group.get_member(b"carol") is None

    def test_commit_epoch_mismatch_fails(self, backend: HKDFMLSBackend) -> None:
        """Proposals from wrong epoch fail on commit."""
        backend.create_group(b"g", b"alice")
        backend.propose_add(b"g", b"alice", b"bob", b"kp")

        # Advance epoch by adding another member directly
        backend.add_member(b"g", b"carol", b"carol-kp")

        # Now the pending proposal has epoch 0, but group is at epoch 1
        with pytest.raises(MLSEpochMismatchError):
            backend.commit(b"g", b"alice")

    def test_commit_nonmember_fails(self, backend: HKDFMLSBackend) -> None:
        """Non-member can't commit."""
        backend.create_group(b"g", b"alice")

        with pytest.raises(MLSMemberNotFoundError):
            backend.commit(b"g", b"outsider")

    def test_process_commit(self, backend: HKDFMLSBackend) -> None:
        """Process commit advances epoch for non-committing members."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        # Alice proposes and commits (epoch goes from 1 to 2)
        backend.propose_add(b"g", b"alice", b"carol", b"kp2")
        group, commit = backend.commit(b"g", b"alice")

        # Simulate another backend at the same epoch as when the commit was created
        backend2 = HKDFMLSBackend()
        backend2.create_group(b"g", b"alice")
        backend2.add_member(b"g", b"bob", b"kp")
        # backend2 is at epoch 1 — same as commit.epoch

        result = backend2.process_commit(b"g", commit)
        assert result.epoch == commit.epoch + 1

    def test_process_commit_epoch_mismatch(self, backend: HKDFMLSBackend) -> None:
        """Process commit with wrong epoch fails."""
        backend.create_group(b"g", b"alice")
        backend.add_member(b"g", b"bob", b"kp")

        from our_crypto.mls import MLSCommit

        wrong_commit = MLSCommit(
            group_id=b"g",
            epoch=999,
            proposals=[],
            committer=b"alice",
            commit_secret=b"\x00" * 32,
        )

        with pytest.raises(MLSEpochMismatchError):
            backend.process_commit(b"g", wrong_commit)


class TestHKDFMLSBackendKeySchedule:
    """Tests for HKDF key schedule properties."""

    @pytest.fixture
    def backend(self) -> HKDFMLSBackend:
        return HKDFMLSBackend()

    def test_application_key_derivation(self, backend: HKDFMLSBackend) -> None:
        """Application key derivation works from real HKDF schedule."""
        backend.create_group(b"g", b"alice")
        ks = backend.get_key_schedule(b"g")

        key0 = ks.derive_application_key(0)
        key1 = ks.derive_application_key(1)

        assert len(key0) == 32
        assert key0 != key1  # Different generations, different keys

    def test_nonce_derivation(self, backend: HKDFMLSBackend) -> None:
        """Nonce derivation produces 12-byte values."""
        backend.create_group(b"g", b"alice")
        ks = backend.get_key_schedule(b"g")

        nonce = ks.derive_nonce(0)
        assert len(nonce) == 12

    def test_export_secret(self, backend: HKDFMLSBackend) -> None:
        """Secret export produces correct-length output."""
        backend.create_group(b"g", b"alice")
        ks = backend.get_key_schedule(b"g")

        exported = ks.export_secret(b"label", b"context", 48)
        assert len(exported) == 48

    def test_epoch_ratchet_is_one_way(self, backend: HKDFMLSBackend) -> None:
        """Epoch secrets ratchet forward — old secrets can't derive new ones."""
        backend.create_group(b"g", b"alice")
        ks0 = backend.get_key_schedule(b"g")

        backend.add_member(b"g", b"bob", b"kp")
        ks1 = backend.get_key_schedule(b"g")

        backend.add_member(b"g", b"carol", b"kp2")
        ks2 = backend.get_key_schedule(b"g")

        # All epoch secrets are distinct
        secrets = {ks0.epoch_secret, ks1.epoch_secret, ks2.epoch_secret}
        assert len(secrets) == 3

    def test_get_nonexistent_group_fails(self, backend: HKDFMLSBackend) -> None:
        """Getting key schedule for nonexistent group fails."""
        with pytest.raises(MLSGroupNotFoundError):
            backend.get_key_schedule(b"missing")


class TestHKDFMLSBackendLifecycle:
    """Full lifecycle tests."""

    @pytest.fixture
    def backend(self) -> HKDFMLSBackend:
        return HKDFMLSBackend()

    def test_full_group_lifecycle(self, backend: HKDFMLSBackend) -> None:
        """Create -> add members -> update -> remove -> verify epoch progression."""
        group = backend.create_group(b"g", b"alice")
        assert group.epoch == 0

        group = backend.add_member(b"g", b"bob", b"kp1")
        assert group.epoch == 1
        assert group.member_count == 2

        group = backend.add_member(b"g", b"carol", b"kp2")
        assert group.epoch == 2
        assert group.member_count == 3

        group = backend.update_keys(b"g", b"alice")
        assert group.epoch == 3

        group = backend.remove_member(b"g", b"carol", b"alice")
        assert group.epoch == 4
        assert group.member_count == 2

    def test_multi_group_isolation(self, backend: HKDFMLSBackend) -> None:
        """Operations on one group don't affect another."""
        backend.create_group(b"g1", b"alice")
        backend.create_group(b"g2", b"bob")

        backend.add_member(b"g1", b"carol", b"kp")

        g1 = backend.get_group(b"g1")
        g2 = backend.get_group(b"g2")

        assert g1 is not None and g1.epoch == 1
        assert g2 is not None and g2.epoch == 0

    def test_clear(self, backend: HKDFMLSBackend) -> None:
        """Clear resets all backend state."""
        backend.create_group(b"g", b"alice")
        backend.clear()

        assert backend.get_group(b"g") is None

    def test_get_group_returns_none_for_unknown(self, backend: HKDFMLSBackend) -> None:
        """get_group returns None for unknown group."""
        assert backend.get_group(b"unknown") is None
