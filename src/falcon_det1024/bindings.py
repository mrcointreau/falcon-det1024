"""Low-level bindings: thin, type-checked wrappers over the det1024 C API.

This is the public low-level layer (in the spirit of `nacl.bindings`). Each
function maps 1:1 to a `falcon_det1024_*` C function, keeping the C name with
the `falcon_det1024_` prefix dropped, and operates on raw bytes with no domain
separation. The ergonomic `FalconSigner` / `FalconVerifier` classes are built
on top of these.

Every function enforces exact input lengths before calling into C. Several
det1024 functions take no length argument for their fixed-size buffers and do
no bounds check (they read or write a hard-coded number of bytes), so an
undersized input would cause an out-of-bounds access in C. The required lengths
mirror what `deterministic.c` reads and writes.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from . import exceptions as exc
from ._lib import err_name, ffi, lib
from .constants import (
    COMPRESSED_SIG_MAX_SIZE,
    CT_SIGNATURE_SIZE,
    CURRENT_SALT_VERSION,
    N,
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
    SEED_SIZE,
)

__all__ = [
    "keygen_from_seed",
    "keygen_from_system",
    "sign_compressed",
    "verify_compressed",
    "verify_ct",
    "convert_compressed_to_ct",
    "get_salt_version",
    "pubkey_coeffs",
    "hash_to_point_coeffs",
    "s2_coeffs",
    "s1_coeffs",
]


def _as_bytes(name: str, value: object) -> bytes:
    """Normalize a bytes-like argument to `bytes`.

    cffi accepts a `bytes` for a `const void *` parameter but rejects
    `bytearray` and `memoryview`, so the conversion here lets the whole surface
    accept any bytes-like object. `int` is rejected: `bytes(5)` would silently
    produce a 5-byte zero buffer, which could pass a length check.
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


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def _keygen(rng: Any) -> tuple[bytes, bytes]:
    priv = ffi.new("uint8_t[]", PRIVATE_KEY_SIZE)
    pub = ffi.new("uint8_t[]", PUBLIC_KEY_SIZE)
    rc = int(lib.falcon_det1024_keygen(rng, priv, pub))
    if rc != 0:
        raise exc.KeygenError(f"keygen failed: {err_name(rc)}")
    return (
        bytes(ffi.buffer(priv, PRIVATE_KEY_SIZE)),
        bytes(ffi.buffer(pub, PUBLIC_KEY_SIZE)),
    )


def keygen_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Deterministically derive a (private_key, public_key) pair from a seed."""
    seed = _as_bytes("seed", seed)
    _check_len("seed", seed, SEED_SIZE)
    rng = ffi.new("shake256_context *")
    lib.shake256_init_prng_from_seed(rng, seed, len(seed))
    return _keygen(rng)


def keygen_from_system() -> tuple[bytes, bytes]:
    """Generate a (private_key, public_key) pair seeded from the OS RNG."""
    rng = ffi.new("shake256_context *")
    rc = int(lib.shake256_init_prng_from_system(rng))
    if rc != 0:
        raise exc.KeygenError(f"system RNG initialization failed: {err_name(rc)}")
    return _keygen(rng)


# --------------------------------------------------------------------------- #
# Sign / verify / convert
# --------------------------------------------------------------------------- #
def sign_compressed(private_key: bytes, data: bytes) -> bytes:
    """Deterministically sign `data` and return a variable-length compressed signature."""
    private_key = _as_bytes("private_key", private_key)
    data = _as_bytes("data", data)
    _check_len("private_key", private_key, PRIVATE_KEY_SIZE)
    sig = ffi.new("uint8_t[]", COMPRESSED_SIG_MAX_SIZE)
    sig_len = ffi.new("size_t *")
    rc = int(
        lib.falcon_det1024_sign_compressed(
            sig, sig_len, private_key, data, len(data)
        )
    )
    if rc != 0:
        raise exc.SigningError(f"signing failed: {err_name(rc)}")
    return bytes(ffi.buffer(sig, sig_len[0]))


def verify_compressed(public_key: bytes, data: bytes, signature: bytes) -> None:
    """Verify a compressed signature and raise `InvalidSignature` on failure."""
    public_key = _as_bytes("public_key", public_key)
    data = _as_bytes("data", data)
    signature = _as_bytes("signature", signature)
    _check_len("public_key", public_key, PUBLIC_KEY_SIZE)
    if len(signature) < 2:
        raise exc.InvalidSignature("signature is too short")
    rc = int(
        lib.falcon_det1024_verify_compressed(
            signature, len(signature), public_key, data, len(data)
        )
    )
    if rc != 0:
        raise exc.InvalidSignature(f"verification failed: {err_name(rc)}")


def verify_ct(public_key: bytes, data: bytes, signature: bytes) -> None:
    """Verify a CT-format signature and raise `InvalidSignature` on failure.

    `falcon_det1024_verify_ct` takes no length argument (CT is fixed at 1538
    bytes and reads them unconditionally), so the exact-length check is required
    for memory safety, not only validation.
    """
    public_key = _as_bytes("public_key", public_key)
    data = _as_bytes("data", data)
    signature = _as_bytes("signature", signature)
    _check_len("public_key", public_key, PUBLIC_KEY_SIZE)
    _check_len("CT signature", signature, CT_SIGNATURE_SIZE)
    rc = int(lib.falcon_det1024_verify_ct(signature, public_key, data, len(data)))
    if rc != 0:
        raise exc.InvalidSignature(f"CT verification failed: {err_name(rc)}")


def convert_compressed_to_ct(signature: bytes) -> bytes:
    """Convert a compressed signature to fixed-length CT format (1538 bytes)."""
    signature = _as_bytes("signature", signature)
    if len(signature) < 2:
        raise exc.ConversionError("signature is too short")
    if len(signature) > COMPRESSED_SIG_MAX_SIZE:
        raise ValueError(
            f"compressed signature too long (> {COMPRESSED_SIG_MAX_SIZE} bytes)"
        )
    sig_ct = ffi.new("uint8_t[]", CT_SIGNATURE_SIZE)
    rc = int(
        lib.falcon_det1024_convert_compressed_to_ct(sig_ct, signature, len(signature))
    )
    if rc != 0:
        raise exc.ConversionError(f"conversion to CT failed: {err_name(rc)}")
    return bytes(ffi.buffer(sig_ct, CT_SIGNATURE_SIZE))


def get_salt_version(signature: bytes) -> int:
    """Return the salt-version byte (index 1); works on either signature format."""
    signature = _as_bytes("signature", signature)
    if len(signature) < 2:
        raise ValueError("signature must be at least 2 bytes to read the salt version")
    return int(lib.falcon_det1024_get_salt_version(signature))


# --------------------------------------------------------------------------- #
# Coefficient (advanced, low-level) helpers. All coeff vectors have length N.
# --------------------------------------------------------------------------- #
def pubkey_coeffs(public_key: bytes) -> list[int]:
    """Unpack a public key into its N ring-element coefficients (h)."""
    public_key = _as_bytes("public_key", public_key)
    _check_len("public_key", public_key, PUBLIC_KEY_SIZE)
    h = ffi.new("uint16_t[]", N)
    rc = int(lib.falcon_det1024_pubkey_coeffs(h, public_key))
    if rc != 0:
        raise exc.FalconError(f"pubkey_coeffs failed: {err_name(rc)}")
    return [int(x) for x in h]


def hash_to_point_coeffs(
    data: bytes, salt_version: int = CURRENT_SALT_VERSION
) -> list[int]:
    """Hash `data` (with the fixed versioned salt) to N ring coefficients (c)."""
    data = _as_bytes("data", data)
    if not 0 <= salt_version <= 255:
        raise ValueError("salt_version must be in range 0..255")
    c = ffi.new("uint16_t[]", N)
    lib.falcon_det1024_hash_to_point_coeffs(c, data, len(data), salt_version)
    return [int(x) for x in c]


def s2_coeffs(ct_signature: bytes) -> list[int]:
    """Unpack the N s2 coefficients from a CT-format signature.

    CT format only. It reads a fixed 1538 bytes with no length argument, so the
    exact-length check is required for memory safety.
    """
    ct_signature = _as_bytes("CT signature", ct_signature)
    _check_len("CT signature", ct_signature, CT_SIGNATURE_SIZE)
    s2 = ffi.new("int16_t[]", N)
    rc = int(lib.falcon_det1024_s2_coeffs(s2, ct_signature))
    if rc != 0:
        raise exc.FalconError(f"s2_coeffs failed: {err_name(rc)}")
    return [int(x) for x in s2]


def s1_coeffs(h: Sequence[int], c: Sequence[int], s2: Sequence[int]) -> list[int]:
    """Compute s1 = c - s2*h and return its N coefficients.

    Raise `InvalidSignature` if the aggregate (s1, s2) vector is not short enough
    to constitute a valid signature.
    """
    for name, seq in (("h", h), ("c", c), ("s2", s2)):
        if len(seq) != N:
            raise ValueError(
                f"{name} must have exactly {N} coefficients, got {len(seq)}"
            )
    # h and c are uint16_t and s2 is int16_t; an out-of-range coefficient makes
    # cffi raise OverflowError. Re-raise it as ValueError so callers get the
    # module's usual bad-input type.
    try:
        h_arr = ffi.new("uint16_t[]", list(h))
        c_arr = ffi.new("uint16_t[]", list(c))
        s2_arr = ffi.new("int16_t[]", list(s2))
    except OverflowError as e:
        raise ValueError(f"coefficient out of range for its C type: {e}") from e
    s1 = ffi.new("int16_t[]", N)
    rc = int(lib.falcon_det1024_s1_coeffs(s1, h_arr, c_arr, s2_arr))
    if rc != 0:
        raise exc.InvalidSignature(
            f"s1_coeffs: aggregate vector is not a valid short signature: "
            f"{err_name(rc)}"
        )
    return [int(x) for x in s1]
