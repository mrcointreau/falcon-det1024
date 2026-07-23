"""Private cffi marshalling for the det1024 operations the package exposes.

`FalconSigner` and `FalconVerifier` in `api.py` are the supported surface; this
module is internal. It binds the C functions behind them: keygen, public-key
recomputation, compressed signing, and compressed verification.

Every fixed-size buffer is length-checked before the call. `falcon_det1024_keygen`
writes 2305 and 1793 bytes unconditionally and `sign_compressed` reads a 2305-byte
private key with no length argument, so an undersized input would be an
out-of-bounds access in C. The required lengths mirror what `deterministic.c`
reads and writes.
"""

from __future__ import annotations

import os

from . import exceptions as exc
from ._lib import err_name, ffi, lib
from .constants import (
    COMPRESSED_SIG_MAX_SIZE,
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
)

# Length of the randomly generated seed used when no seed is supplied. The seed
# only has to saturate the SHAKE256 PRNG that `keygen` draws from, so 384 bits
# sits comfortably above the scheme's security level.
_RANDOM_SEED_SIZE = 48


def _as_bytes(name: str, value: object) -> bytes:
    """Normalize a bytes-like argument to `bytes`.

    cffi accepts a `bytes` for a `const void *` parameter but rejects
    `bytearray` and `memoryview`, so the conversion here accepts those two as
    well. `int` is rejected: `bytes(5)` would silently produce a 5-byte zero
    buffer, which could pass a length check.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        f"{name} must be bytes-like (bytes, bytearray, memoryview), "
        f"got {type(value).__name__}"
    )


def _check_len(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise ValueError(
            f"{name} must be exactly {expected} bytes, got {len(value)}"
        )


def keygen(seed: bytes | None = None) -> bytes:
    """Derive a private key from `seed`.

    `seed` may be any non-empty length: C's `shake256_init_prng_from_seed` takes
    the length explicitly and imposes no size of its own. With `seed=None` a
    fresh `_RANDOM_SEED_SIZE`-byte seed is taken from the OS CSPRNG.
    """
    if seed is None:
        seed = os.urandom(_RANDOM_SEED_SIZE)
    else:
        seed = _as_bytes("seed", seed)
        if not seed:
            raise ValueError("seed must not be empty (pass seed=None to randomize)")

    rng = ffi.new("shake256_context *")
    lib.shake256_init_prng_from_seed(rng, seed, len(seed))

    priv = ffi.new("uint8_t[]", PRIVATE_KEY_SIZE)
    # C writes the public key alongside the private one and offers no mode that
    # skips it. The result is discarded rather than returned so that deriving it
    # from the private key stays the only way a keypair is ever assembled.
    pub = ffi.new("uint8_t[]", PUBLIC_KEY_SIZE)
    rc = int(lib.falcon_det1024_keygen(rng, priv, pub))
    if rc != 0:
        raise exc.KeygenError(f"keygen failed: {err_name(rc)}")
    return bytes(ffi.buffer(priv, PRIVATE_KEY_SIZE))


def public_key_from_private(private_key: bytes) -> bytes:
    """Recompute the public key that belongs to `private_key`.

    Binds `falcon_make_public`. Deriving rather than storing the public key is
    what makes a mismatched keypair unrepresentable: an Algorand address is
    derived from the *public* key, so a signer holding an unrelated private key
    would produce signatures that can never authorize it.
    """
    private_key = _as_bytes("private_key", private_key)
    _check_len("private_key", private_key, PRIVATE_KEY_SIZE)
    pub = ffi.new("uint8_t[]", PUBLIC_KEY_SIZE)
    tmp = ffi.new("uint8_t[]", int(lib.FALCON_DET1024_TMPSIZE_MAKEPUB))
    rc = int(
        lib.falcon_make_public(
            pub, PUBLIC_KEY_SIZE, private_key, len(private_key), tmp, len(tmp)
        )
    )
    if rc != 0:
        raise exc.KeygenError(
            f"could not derive the public key from the private key: {err_name(rc)}"
        )
    return bytes(ffi.buffer(pub, PUBLIC_KEY_SIZE))


def sign_compressed(private_key: bytes, message: bytes) -> bytes:
    """Deterministically sign `message`, returning a variable-length signature."""
    private_key = _as_bytes("private_key", private_key)
    message = _as_bytes("message", message)
    _check_len("private_key", private_key, PRIVATE_KEY_SIZE)
    sig = ffi.new("uint8_t[]", COMPRESSED_SIG_MAX_SIZE)
    sig_len = ffi.new("size_t *")
    rc = int(
        lib.falcon_det1024_sign_compressed(
            sig, sig_len, private_key, message, len(message)
        )
    )
    if rc != 0:
        raise exc.SigningError(f"signing failed: {err_name(rc)}")
    return bytes(ffi.buffer(sig, sig_len[0]))


def verify_compressed(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify a compressed signature, raising `InvalidSignature` on failure."""
    public_key = _as_bytes("public_key", public_key)
    message = _as_bytes("message", message)
    signature = _as_bytes("signature", signature)
    _check_len("public_key", public_key, PUBLIC_KEY_SIZE)
    rc = int(
        lib.falcon_det1024_verify_compressed(
            signature, len(signature), public_key, message, len(message)
        )
    )
    if rc != 0:
        raise exc.InvalidSignature(f"verification failed: {err_name(rc)}")
