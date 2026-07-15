"""Shared fixtures and helpers for the falcon-det1024 test suite."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp

# A fixed seed so the keypair (and thus signatures) are stable across the suite.
SEED = bytes(range(32))


@pytest.fixture(scope="session")
def signer() -> fp.FalconSigner:
    return fp.FalconSigner.generate(seed=SEED)


@pytest.fixture(scope="session")
def verifier(signer: fp.FalconSigner) -> fp.FalconVerifier:
    return signer.verifying_key()
