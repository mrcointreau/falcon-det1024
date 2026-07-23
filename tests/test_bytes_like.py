"""The API accepts any bytes-like object (bytes / bytearray / memoryview) and
rejects non-bytes-like types cleanly (no silent zero-length-buffer footgun)."""

from __future__ import annotations

import pytest

import falcon_det1024 as fp
from falcon_det1024 import _bindings


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
    s = fp.FalconSigner(bytearray(signer.private_key))
    assert s.public_key == signer.public_key
    assert fp.FalconSigner(memoryview(signer.private_key)).public_key == v.public_key


def test_constructor_stores_the_key_the_public_key_was_derived_from(
    signer: fp.FalconSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Accepting a bytearray means the caller can still write to it. Stand in for
    # a concurrent writer by overwriting the buffer the moment the public key
    # has been read out of it: the signer must keep the key it derived from,
    # never the one substituted behind its back.
    derive = _bindings.public_key_from_private
    theirs = fp.FalconSigner.generate(seed=b"substituted").private_key
    buf = bytearray(signer.private_key)
    derivations: list[bytes] = []

    def derive_then_overwrite(private_key: bytes) -> bytes:
        public_key = derive(private_key)
        derivations.append(public_key)
        buf[:] = theirs
        return public_key

    monkeypatch.setattr(_bindings, "public_key_from_private", derive_then_overwrite)
    rebuilt = fp.FalconSigner(buf)

    assert len(derivations) == 1, "the constructor must derive the key it stores"
    assert rebuilt.private_key == signer.private_key
    assert rebuilt.public_key == derive(rebuilt.private_key)


@pytest.mark.parametrize("name", ["seed", "message", "signature"])
def test_int_is_rejected_at_every_entry_point(
    signer: fp.FalconSigner, verifier: fp.FalconVerifier, name: str
) -> None:
    # bytes(5) would silently become five zero bytes, so `generate(seed=5)`
    # must not quietly derive a key from a five-byte zero seed.
    with pytest.raises(TypeError, match=name):
        if name == "seed":
            fp.FalconSigner.generate(seed=5)  # type: ignore[arg-type]
        elif name == "message":
            signer.sign(5)  # type: ignore[arg-type]
        else:
            verifier.verify(b"m", 5)  # type: ignore[arg-type]


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
        fp.FalconSigner(2305)  # type: ignore[arg-type]
