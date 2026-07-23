"""Rejection of tampered signatures, wrong messages, and wrong keys."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp

MSG = b"the message under signature"


@pytest.fixture(scope="module")
def sig(signer: fp.FalconSigner) -> bytes:
    return signer.sign(MSG)


@pytest.mark.parametrize("pos", [0, 1, 2, 10, 100, -1])
def test_single_byte_flip_rejected(
    verifier: fp.FalconVerifier, sig: bytes, pos: int
) -> None:
    bad = bytearray(sig)
    bad[pos] ^= 0x01
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG, bytes(bad))
    assert verifier.is_valid(MSG, bytes(bad)) is False


def test_wrong_message_rejected(verifier: fp.FalconVerifier, sig: bytes) -> None:
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG + b"!", sig)


def test_wrong_key_rejected(sig: bytes) -> None:
    other = fp.FalconSigner.generate(seed=bytes([9] * 32)).verifying_key()
    with pytest.raises(fp.InvalidSignature):
        other.verify(MSG, sig)


def test_truncated_signature_rejected(verifier: fp.FalconVerifier, sig: bytes) -> None:
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG, sig[:1])  # < 2 bytes
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG, sig[:-1])  # truncated body


@pytest.mark.parametrize("length", [0, 1])
def test_signature_below_header_size_is_rejected_by_c(
    verifier: fp.FalconVerifier, sig: bytes, length: int
) -> None:
    # A signature too short to hold the header byte is handed straight to
    # `falcon_det1024_verify_compressed`, whose own `sig_len < 2` branch returns
    # BADSIG before dereferencing `sig[0]`. Matching on the error code is what
    # shows the rejection came from C rather than a Python pre-check.
    with pytest.raises(fp.InvalidSignature, match="FALCON_ERR_BADSIG"):
        verifier.verify(MSG, sig[:length])


def test_corrupted_header_rejected(verifier: fp.FalconVerifier, sig: bytes) -> None:
    bad = bytearray(sig)
    bad[0] = 0x00  # wrong header byte
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG, bytes(bad))


def test_empty_signature_rejected(verifier: fp.FalconVerifier) -> None:
    with pytest.raises(fp.InvalidSignature):
        verifier.verify(MSG, b"")
