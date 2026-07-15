"""CT-format conversion, the CT verify path, and coefficient helpers.

CT is a fixed-length (1538 byte) serialization used for hashing and Merkle
trees. It is not exposed as a top-level verify path, so the CT verify function
is exercised here via the internal `_core` module.
"""

from __future__ import annotations

import pytest

import falcon_det1024 as fp
from falcon_det1024 import _core

MSG = b"convert me to CT"


@pytest.fixture(scope="module")
def sig(signer: fp.FalconSigner) -> bytes:
    return signer.sign(MSG)


@pytest.fixture(scope="module")
def ct(sig: bytes) -> bytes:
    return fp.compressed_to_ct(sig)


def test_ct_shape(ct: bytes) -> None:
    assert len(ct) == fp.CT_SIGNATURE_SIZE == 1538
    assert ct[0] == (0x5A | 0x80)  # det1024 CT header
    assert fp.salt_version(ct) == fp.CURRENT_SALT_VERSION


def test_salt_version_on_both_formats(sig: bytes, ct: bytes) -> None:
    assert fp.salt_version(sig) == fp.salt_version(ct) == 0


def test_ct_verifies(signer: fp.FalconSigner, ct: bytes) -> None:
    # internal CT verify path accepts the converted signature
    assert _core.verify_ct(signer.public_key, MSG, ct) is None


def test_ct_tamper_rejected(signer: fp.FalconSigner, ct: bytes) -> None:
    bad = bytearray(ct)
    bad[100] ^= 0x01
    with pytest.raises(fp.InvalidSignature):
        _core.verify_ct(signer.public_key, MSG, bytes(bad))


def test_ct_wrong_length_rejected(signer: fp.FalconSigner, ct: bytes) -> None:
    # verify_ct reads a fixed 1538 bytes with no length argument (exact-length guard).
    with pytest.raises(ValueError):
        _core.verify_ct(signer.public_key, MSG, ct[:-1])


def test_pubkey_coeffs(signer: fp.FalconSigner) -> None:
    h = fp.pubkey_coeffs(signer.public_key)
    assert len(h) == fp.N
    assert all(0 <= x < 12289 for x in h)  # coefficients mod q


def test_hash_to_point_coeffs_deterministic() -> None:
    a = fp.hash_to_point_coeffs(MSG)
    b = fp.hash_to_point_coeffs(MSG)
    assert a == b == fp.hash_to_point_coeffs(MSG, fp.CURRENT_SALT_VERSION)
    assert len(a) == fp.N
    assert all(0 <= x < 12289 for x in a)
    assert fp.hash_to_point_coeffs(b"different") != a


def test_s2_and_s1_coeffs_roundtrip(signer: fp.FalconSigner, ct: bytes) -> None:
    h = fp.pubkey_coeffs(signer.public_key)
    c = fp.hash_to_point_coeffs(MSG)
    s2 = fp.s2_coeffs(ct)
    assert len(s2) == fp.N
    # s1 = c - s2*h; succeeds only if (s1, s2) is a valid short vector
    s1 = fp.s1_coeffs(h, c, s2)
    assert len(s1) == fp.N


def test_convert_rejects_bad_input() -> None:
    with pytest.raises(fp.ConversionError):
        fp.compressed_to_ct(b"\x00")  # too short
    with pytest.raises(fp.ConversionError):
        fp.compressed_to_ct(b"\x00" * 100)  # wrong header / undecodable


def test_s2_coeffs_rejects_non_ct(sig: bytes, ct: bytes) -> None:
    # A compressed signature is not 1538 bytes, so the length guard raises ValueError.
    with pytest.raises(ValueError):
        fp.s2_coeffs(sig)
    # Right length but wrong header raises FalconError (FORMAT) from C.
    bad = bytearray(ct)
    bad[0] = 0x00
    with pytest.raises(fp.FalconError):
        fp.s2_coeffs(bytes(bad))
