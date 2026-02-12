"""Shared test fixtures for our-crypto."""

import pytest

from our_crypto.mls import MockMLSBackend
from our_crypto.mls_real import HKDFMLSBackend
from our_crypto.pre import MockPREBackend
from our_crypto.pre_real import X25519PREBackend
from our_crypto.zkp import MockZKPBackend
from our_crypto.zkp_real import SigmaZKPBackend


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "unit: Unit tests (no external dependencies)")
    config.addinivalue_line("markers", "integration: Integration tests (require external services)")
    config.addinivalue_line("markers", "slow: Slow tests (>5s)")


# =============================================================================
# Parameterized backend fixtures (mock vs real)
# =============================================================================


@pytest.fixture(params=["mock", "x25519"], ids=["pre-mock", "pre-x25519"])
def pre_backend(request: pytest.FixtureRequest) -> MockPREBackend | X25519PREBackend:
    """Parameterized PRE backend fixture (mock and real)."""
    if request.param == "mock":
        return MockPREBackend()
    else:
        return X25519PREBackend()


@pytest.fixture(params=["mock", "hkdf"], ids=["mls-mock", "mls-hkdf"])
def mls_backend(request: pytest.FixtureRequest) -> MockMLSBackend | HKDFMLSBackend:
    """Parameterized MLS backend fixture (mock and real)."""
    if request.param == "mock":
        return MockMLSBackend()
    else:
        return HKDFMLSBackend()


@pytest.fixture(params=["mock", "sigma"], ids=["zkp-mock", "zkp-sigma"])
def zkp_backend(request: pytest.FixtureRequest) -> MockZKPBackend | SigmaZKPBackend:
    """Parameterized ZKP backend fixture (mock and real)."""
    if request.param == "mock":
        return MockZKPBackend()
    else:
        return SigmaZKPBackend()
