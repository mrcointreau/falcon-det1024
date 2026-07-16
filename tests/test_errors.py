"""Boundary validation and the exception hierarchy."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp


def test_exception_hierarchy() -> None:
    for exc in (
        fp.InvalidSignature,
        fp.KeygenError,
        fp.SigningError,
        fp.ConversionError,
    ):
        assert issubclass(exc, fp.FalconError)
    assert issubclass(fp.FalconError, Exception)


@pytest.mark.parametrize("bad_seed", [b"", b"short", bytes(31), bytes(33), bytes(64)])
def test_generate_rejects_wrong_seed_length(bad_seed: bytes) -> None:
    with pytest.raises(ValueError):
        fp.FalconSigner.generate(seed=bad_seed)


@pytest.mark.parametrize("bad_key", [b"", bytes(1792), bytes(1794)])
def test_verifier_rejects_wrong_public_key_length(bad_key: bytes) -> None:
    with pytest.raises(ValueError):
        fp.FalconVerifier(bad_key)


def test_signer_rejects_wrong_key_lengths(signer: fp.FalconSigner) -> None:
    with pytest.raises(ValueError):
        fp.FalconSigner(bytes(2304), signer.public_key)
    with pytest.raises(ValueError):
        fp.FalconSigner(signer.private_key, bytes(1792))


def test_verify_compressed_rejects_wrong_public_key_length(
    signer: fp.FalconSigner,
) -> None:
    sig = signer.sign(b"x")
    with pytest.raises(ValueError):
        fp.bindings.verify_compressed(bytes(10), b"x", sig)


def test_get_salt_version_requires_two_bytes() -> None:
    with pytest.raises(ValueError):
        fp.bindings.get_salt_version(b"\x00")


def test_pubkey_coeffs_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        fp.bindings.pubkey_coeffs(bytes(10))


def test_s1_coeffs_rejects_wrong_vector_length(signer: fp.FalconSigner) -> None:
    good = fp.bindings.pubkey_coeffs(signer.public_key)
    with pytest.raises(ValueError):
        fp.bindings.s1_coeffs(good[:-1], good, good)


def test_s1_coeffs_rejects_out_of_range_coefficient(signer: fp.FalconSigner) -> None:
    h = fp.bindings.pubkey_coeffs(signer.public_key)
    c = fp.bindings.hash_to_point_coeffs(b"x")
    s2 = [0] * fp.N
    # An out-of-range uint16 (h) raises ValueError, not OverflowError.
    with pytest.raises(ValueError):
        fp.bindings.s1_coeffs([70000, *h[1:]], c, s2)
    # out-of-range int16 (s2)
    with pytest.raises(ValueError):
        fp.bindings.s1_coeffs(h, c, [40000, *s2[1:]])


def test_hash_to_point_coeffs_rejects_bad_salt_version() -> None:
    with pytest.raises(ValueError):
        fp.bindings.hash_to_point_coeffs(b"x", salt_version=256)
    with pytest.raises(ValueError):
        fp.bindings.hash_to_point_coeffs(b"x", salt_version=-1)
