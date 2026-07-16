"""Sign/verify roundtrip and public-surface behaviour."""

from __future__ import annotations

import os

import pytest

import falcon_det1024 as fp

MESSAGES = [b"", b"\x00", b"hello world", os.urandom(32), os.urandom(1024), b"\xff" * 4096]


@pytest.mark.parametrize("message", MESSAGES)
def test_sign_verify_roundtrip(
    signer: fp.FalconSigner, verifier: fp.FalconVerifier, message: bytes
) -> None:
    sig = signer.sign(message)
    assert isinstance(sig, bytes)
    assert 2 <= len(sig) <= fp.COMPRESSED_SIG_MAX_SIZE
    assert sig[0] == (0x3A | 0x80)  # det1024 compressed header
    assert fp.bindings.get_salt_version(sig) == fp.CURRENT_SALT_VERSION
    # verify() returns None on success (does not raise)
    assert verifier.verify(message, sig) is None
    assert verifier.is_valid(message, sig) is True


@pytest.mark.parametrize("message", MESSAGES)
def test_bindings_verify_compressed(signer: fp.FalconSigner, message: bytes) -> None:
    sig = signer.sign(message)
    assert fp.bindings.verify_compressed(signer.public_key, message, sig) is None


def test_verifier_from_public_key(signer: fp.FalconSigner) -> None:
    msg = b"reconstructed verifier"
    sig = signer.sign(msg)
    v = fp.FalconVerifier(signer.public_key)
    v.verify(msg, sig)


def test_signer_reconstructed_from_keypair(signer: fp.FalconSigner) -> None:
    rebuilt = fp.FalconSigner(signer.private_key, signer.public_key)
    msg = b"same key, same signature"
    assert rebuilt.sign(msg) == signer.sign(msg)
    assert rebuilt.public_key == signer.public_key


def test_verifier_equality_and_hash(signer: fp.FalconSigner) -> None:
    a = signer.verifying_key()
    b = fp.FalconVerifier(signer.public_key)
    assert a == b
    assert hash(a) == hash(b)
    assert a != fp.FalconSigner.generate(seed=bytes([1] * 32)).verifying_key()
    assert a != "not a verifier"


def test_repr_hides_secret(signer: fp.FalconSigner) -> None:
    # repr must not leak raw key material
    assert signer.private_key.hex() not in repr(signer)
    assert "bytes" in repr(signer)
    assert "bytes" in repr(signer.verifying_key())
