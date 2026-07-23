"""Boundary validation and the exception hierarchy."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp
from falcon_det1024 import _bindings


def test_exception_hierarchy() -> None:
    for exc in (fp.InvalidSignature, fp.KeygenError, fp.SigningError):
        assert issubclass(exc, fp.FalconError)
    assert issubclass(fp.FalconError, Exception)


def test_generate_rejects_empty_seed() -> None:
    # An empty seed must not silently fall back to randomness.
    with pytest.raises(ValueError):
        fp.FalconSigner.generate(seed=b"")


@pytest.mark.parametrize("seed", [b"x", bytes(8), bytes(31), bytes(32), bytes(64)])
def test_generate_accepts_any_non_empty_seed_length(seed: bytes) -> None:
    # `shake256_init_prng_from_seed` takes the length explicitly and imposes
    # no size of its own, so any seed a caller already holds stays reproducible.
    signer = fp.FalconSigner.generate(seed=seed)
    assert len(signer.public_key) == fp.PUBLIC_KEY_SIZE


@pytest.mark.parametrize("bad_key", [b"", bytes(1792), bytes(1794)])
def test_verifier_rejects_wrong_public_key_length(bad_key: bytes) -> None:
    with pytest.raises(ValueError):
        fp.FalconVerifier(bad_key)


@pytest.mark.parametrize("bad_key", [b"", bytes(2304), bytes(2306)])
def test_signer_rejects_wrong_private_key_length(bad_key: bytes) -> None:
    with pytest.raises(ValueError):
        fp.FalconSigner(bad_key)


def test_signer_rejects_undecodable_private_key() -> None:
    # Right length, but not a valid encoded private key: an all-zero buffer
    # fails the header-byte check before any polynomial is decoded.
    with pytest.raises(fp.KeygenError):
        fp.FalconSigner(bytes(fp.PRIVATE_KEY_SIZE))


def test_bindings_enforce_key_lengths_before_calling_c() -> None:
    # `sign_compressed` and `verify_compressed` pass their key straight to C,
    # which takes no length argument for it, so these guards are what stand
    # between a short buffer and an out-of-bounds read. The classes validate on
    # construction, but nothing stops a caller reaching the module directly.
    with pytest.raises(ValueError, match="private_key"):
        _bindings.sign_compressed(bytes(10), b"m")
    with pytest.raises(ValueError, match="public_key"):
        _bindings.verify_compressed(bytes(10), b"m", b"\xba\x00")


def test_signing_rejects_a_private_key_that_construction_accepts() -> None:
    # `falcon_make_public` reads only f and g, at the front of the key; F
    # occupies roughly the last 44% and is decoded only when signing. A key
    # corrupted there constructs fine and fails at `sign`, which is the path
    # that raises `SigningError`.
    key = bytearray(fp.FalconSigner.generate(seed=b"corrupt-F").private_key)
    key[-1] ^= 0x01
    signer = fp.FalconSigner(bytes(key))
    with pytest.raises(fp.SigningError):
        signer.sign(b"message")
