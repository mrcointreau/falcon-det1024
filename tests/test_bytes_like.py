"""The API accepts any bytes-like object (bytes / bytearray / memoryview) and
rejects non-bytes-like types cleanly (no silent zero-length-buffer footgun)."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp


def test_sign_and_verify_accept_bytes_like(
    signer: fp.FalconSigner, verifier: fp.FalconVerifier
) -> None:
    msg = b"bytes-like message"
    sig = signer.sign(bytearray(msg))
    assert sig == signer.sign(msg) == signer.sign(memoryview(msg))
    verifier.verify(memoryview(msg), sig)
    verifier.verify(msg, bytearray(sig))
    assert verifier.is_valid(bytearray(msg), memoryview(sig)) is True


def test_generate_accepts_bytes_like_seed() -> None:
    a = fp.FalconSigner.generate(seed=bytearray(range(32)))
    b = fp.FalconSigner.generate(seed=memoryview(bytes(range(32))))
    c = fp.FalconSigner.generate(seed=bytes(range(32)))
    assert a.public_key == b.public_key == c.public_key


def test_constructors_accept_bytes_like(signer: fp.FalconSigner) -> None:
    v = fp.FalconVerifier(bytearray(signer.public_key))
    assert v.public_key == signer.public_key
    s = fp.FalconSigner(bytearray(signer.private_key), memoryview(signer.public_key))
    assert s.public_key == signer.public_key


def test_helpers_accept_bytes_like(signer: fp.FalconSigner) -> None:
    sig = signer.sign(b"x")
    ct = fp.compressed_to_ct(bytearray(sig))
    assert fp.salt_version(bytearray(ct)) == fp.CURRENT_SALT_VERSION
    assert len(fp.pubkey_coeffs(bytearray(signer.public_key))) == fp.N
    assert len(fp.hash_to_point_coeffs(bytearray(b"x"))) == fp.N
    assert len(fp.s2_coeffs(bytearray(ct))) == fp.N


def test_is_valid_never_raises_for_bytes_like_tamper(
    signer: fp.FalconSigner, verifier: fp.FalconVerifier
) -> None:
    tampered = bytearray(signer.sign(b"x"))
    tampered[5] ^= 0x01
    # A bytes-like, tampered signature must return False, not raise TypeError.
    assert verifier.is_valid(b"x", tampered) is False


@pytest.mark.parametrize("bad", [5, 2305, "string", None, 3.14, [0, 1, 2]])
def test_non_bytes_like_rejected_with_typeerror(bad: object) -> None:
    # An int must not silently become a zero-filled buffer of that length.
    with pytest.raises(TypeError):
        fp.FalconVerifier(bad)  # type: ignore[arg-type]


def test_int_does_not_forge_a_zero_key() -> None:
    # bytes(2305) would be a valid-length all-zero key; ensure it's rejected.
    with pytest.raises(TypeError):
        fp.FalconSigner(2305, 1793)  # type: ignore[arg-type]
