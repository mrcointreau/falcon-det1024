"""Determinism guarantees: keygen and signing are reproducible."""

from __future__ import annotations

import os

import pytest

import falcon_det1024 as fp

SEED = bytes(range(32))


def test_keygen_from_seed_is_deterministic() -> None:
    a = fp.FalconSigner.generate(seed=SEED)
    b = fp.FalconSigner.generate(seed=SEED)
    assert a.private_key == b.private_key
    assert a.public_key == b.public_key


def test_different_seed_different_keypair() -> None:
    a = fp.FalconSigner.generate(seed=bytes(32))
    b = fp.FalconSigner.generate(seed=bytes([1] + [0] * 31))
    assert a.public_key != b.public_key
    assert a.private_key != b.private_key


def test_seed_is_used_verbatim_not_padded_or_truncated() -> None:
    # Seeds of any non-empty length are accepted, so the length is part of the
    # input: it is handed to `shake256_init_prng_from_seed` as `len(seed)` and
    # never normalized to a fixed size. These share an all-zero prefix, so
    # padding or truncating to any single length would collapse them onto one
    # keypair.
    seeds = [bytes(8), bytes(31), bytes(32), bytes(64), bytes(32) + b"\x01"]
    keys = {fp.FalconSigner.generate(seed=s).public_key for s in seeds}
    assert len(keys) == len(seeds)


@pytest.mark.parametrize("message", [b"", b"x", os.urandom(64), os.urandom(2048)])
def test_signing_is_byte_identical(signer: fp.FalconSigner, message: bytes) -> None:
    first = signer.sign(message)
    for _ in range(5):
        assert signer.sign(message) == first


def test_determinism_across_fresh_instances() -> None:
    msg = b"consensus needs bit-exact signatures"
    sig1 = fp.FalconSigner.generate(seed=SEED).sign(msg)
    sig2 = fp.FalconSigner.generate(seed=SEED).sign(msg)
    assert sig1 == sig2


def test_system_rng_keygen_is_random_but_valid() -> None:
    a = fp.FalconSigner.generate()
    b = fp.FalconSigner.generate()
    assert a.public_key != b.public_key  # overwhelmingly likely
    msg = b"system rng"
    a.verifying_key().verify(msg, a.sign(msg))
